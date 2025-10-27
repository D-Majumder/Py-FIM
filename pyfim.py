import os
import hashlib
import json
import time
import argparse
import logging
import fnmatch
import configparser
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
LOG_FILE = "py_fim.log"
HASH_ALGORITHM = hashlib.sha256
CONFIG_FILE = "config.ini"

# --- Set up logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger()

# --- Hashing & Ignore Utilities ---

def _hash_file(filepath):
    """Calculates the SHA-256 hash of a file."""
    try:
        hash_obj = HASH_ALGORITHM()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except PermissionError:
        log.warning(f"Permission denied: Could not read {filepath}")
        return None
    except FileNotFoundError:
        return None # File might have been deleted mid-action
    except Exception as e:
        log.error(f"Error hashing {filepath}: {e}")
        return None

def _is_ignored(filepath, job_config):
    """Checks if a file matches any pattern in the ignore list."""
    ignore_list = job_config.get('ignore_patterns', [])
    
    base_ignore = [
        os.path.basename(LOG_FILE), 
        os.path.basename(CONFIG_FILE), 
        "*.json", 
        "*.hash",
        job_config.get('backup_dir_name') # Ignore the backup dir itself
    ]
    
    full_ignore_list = [pattern for pattern in (ignore_list + base_ignore) if pattern]

    # Check against basename and full path
    file_basename = os.path.basename(filepath)
    for pattern in full_ignore_list:
        if fnmatch.fnmatch(file_basename, pattern) or fnmatch.fnmatch(filepath, pattern):
            return True
            
    # Also ignore the root of the backup directory
    if os.path.commonpath([filepath, job_config['backup_dir']]) == job_config['backup_dir']:
        return True
        
    return False

# --- Tamper-Proofing ---

def _verify_baseline_hash(baseline_file):
    """Verifies the integrity of the baseline file itself. Returns True/False."""
    baseline_hash_file = baseline_file + ".hash"
    try:
        if not os.path.exists(baseline_file) or not os.path.exists(baseline_hash_file):
            log.error(f"Baseline file ('{baseline_file}') or hash file ('{baseline_hash_file}') not found.")
            return False

        with open(baseline_hash_file, 'r') as f:
            expected_hash = f.read().strip()
            
        actual_hash = _hash_file(baseline_file)
        
        if expected_hash != actual_hash:
            log.critical("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            log.critical("!!! CRITICAL: BASELINE TAMPERING DETECTED !!!")
            log.critical(f"  The baseline file '{baseline_file}' has been modified!")
            log.critical("  Refusing to run.")
            log.critical("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            return False
        else:
            return True
            
    except Exception as e:
        log.error(f"Error during baseline integrity check: {e}")
        return False

# --- Core Modes ---

def create_baseline(job_name, job_config, force):
    """Scans the directory, creates a secure baseline, and backs up clean files."""
    
    path_to_monitor = job_config['path']
    baseline_file = job_config['baseline_file']
    backup_dir = job_config['backup_dir']
    job_backup_path = os.path.join(backup_dir, job_name)
    baseline_hash_file = baseline_file + ".hash"
    
    if os.path.exists(baseline_file) and not force:
        log.error(f"Baseline file '{baseline_file}' already exists for job '{job_name}'.")
        log.error("Use --force (or -f) to overwrite.")
        return
        
    log.info(f"--- [Job: {job_name}] Creating new baseline for: {path_to_monitor} ---")
    
    # Clean and recreate backup directory for this job
    if os.path.exists(job_backup_path):
        shutil.rmtree(job_backup_path)
    os.makedirs(job_backup_path, exist_ok=True)
    
    baseline = {}
    
    for root, dirs, files in os.walk(path_to_monitor):
        # Don't walk into the backup directory
        if root.startswith(backup_dir):
            continue
            
        for file in files:
            filepath = os.path.join(root, file)
            
            if _is_ignored(filepath, job_config):
                continue
                
            file_hash = _hash_file(filepath)
            
            if file_hash:
                relative_path = os.path.relpath(filepath, path_to_monitor)
                baseline[relative_path] = file_hash
                
                # --- v4 FEATURE: Backup the file ---
                try:
                    backup_file_path = os.path.join(job_backup_path, relative_path)
                    os.makedirs(os.path.dirname(backup_file_path), exist_ok=True)
                    shutil.copy(filepath, backup_file_path)
                except Exception as e:
                    log.error(f"Could not backup file {relative_path}: {e}")
                
    try:
        with open(baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
        log.info(f"Successfully created baseline with {len(baseline)} files.")

        baseline_hash = _hash_file(baseline_file)
        with open(baseline_hash_file, 'w') as f:
            f.write(baseline_hash)
        log.info(f"Secure hash and {len(baseline)} file backups created.")
        
    except Exception as e:
        log.error(f"Could not write baseline files: {e}")

def check_integrity(job_name, job_config):
    """ScANS the directory and compares it against the secure baseline."""
    
    path_to_monitor = job_config['path']
    baseline_file = job_config['baseline_file']
    
    log.info(f"--- [Job: {job_name}] Starting integrity check for: {path_to_monitor} ---")

    if not _verify_baseline_hash(baseline_file):
        return # Tampering detected, stop.
    
    log.info(f"Baseline integrity verified for '{baseline_file}'. Proceeding...")

    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
    except Exception as e:
        log.error(f"Could not read baseline file '{baseline_file}': {e}")
        return

    # Scan current state
    current_state = {}
    for root, dirs, files in os.walk(path_to_monitor):
        if root.startswith(job_config['backup_dir']):
            continue

        for file in files:
            filepath = os.path.join(root, file)
            
            if _is_ignored(filepath, job_config):
                continue
                
            file_hash = _hash_file(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, path_to_monitor)
                current_state[relative_path] = file_hash

    # Compare and find changes
    new_files, deleted_files, modified_files = [], [], []
    found_changes = False

    for filepath, file_hash in current_state.items():
        if filepath not in baseline:
            new_files.append(filepath); found_changes = True
        elif baseline[filepath] != file_hash:
            modified_files.append(filepath); found_changes = True

    for filepath in baseline:
        if filepath not in current_state:
            deleted_files.append(filepath); found_changes = True

    # Report findings
    log.info(f"--- [Job: {job_name}] Integrity Check Complete ---")
    if not found_changes:
        log.info("✅ SUCCESS: All files are unmodified. System integrity is OK.")
    else:
        if modified_files:
            log.critical("!!! MODIFIED FILES DETECTED !!!")
            for file in modified_files: log.warning(f"  - {file}")
        if new_files:
            log.critical("!!! NEW FILES DETECTED !!!")
            for file in new_files: log.warning(f"  - {file}")
        if deleted_files:
            log.critical("!!! DELETED FILES DETECTED !!!")
            for file in deleted_files: log.warning(f"  - {file}")
    log.info("----------------------------------")

# ---
# v4 FEATURE: REAL-TIME MONITORING
# ---
class FIMEventHandler(FileSystemEventHandler):
    """Custom event handler for watchdog with Debouncing and Active Response."""
    
    def __init__(self, job_name, job_config):
        super().__init__()
        self.job_name = job_name
        self.job_config = job_config
        self.path_to_monitor = job_config['path']
        self.baseline_file = job_config['baseline_file']
        self.backup_dir = job_config['backup_dir']
        self.job_backup_path = os.path.join(self.backup_dir, self.job_name)
        self.mode = job_config.get('mode', 'monitor') # monitor or guardian
        
        # --- v4 FEATURE: Event Debouncing ---
        self.last_event_time = {}
        self.debounce_period = 2.0 # 2 seconds

        # Load the baseline into memory
        if not _verify_baseline_hash(self.baseline_file):
            raise Exception(f"Baseline tampering detected for '{self.baseline_file}'. Cannot start watch.")
        with open(self.baseline_file, 'r') as f:
            self.baseline = json.load(f)
        log.info(f"Baseline for '{self.job_name}' loaded. Mode: {self.mode.upper()}. Watching...")

    def on_modified(self, event):
        if event.is_directory: return
        self._handle_event("MODIFIED", event.src_path)

    def on_created(self, event):
        if event.is_directory: return
        self._handle_event("CREATED", event.src_path)

    def on_deleted(self, event):
        if event.is_directory: return
        self._handle_event("DELETED", event.src_path)
    
    def on_moved(self, event):
        if event.is_directory: return
        self._handle_event("DELETED", event.src_path)
        self._handle_event("CREATED", event.dest_path)
        
    def _handle_event(self, event_type, filepath):
        # --- Debouncing Logic ---
        current_time = time.time()
        last_time = self.last_event_time.get(filepath, 0)
        if (current_time - last_time) < self.debounce_period:
            return # Event is a "spam" event, ignore it.
        self.last_event_time[filepath] = current_time

        # --- Ignore & Path Logic ---
        if _is_ignored(filepath, self.job_config):
            return
            
        try:
            relative_path = os.path.relpath(filepath, self.path_to_monitor)
        except ValueError:
            # This can happen if the file is outside the monitored path (e.g., temp file)
            return 
            
        original_hash = self.baseline.get(relative_path)
        
        # --- Event Triage ---
        
        if event_type == "CREATED":
            log.critical(f"!!! [Job: {self.job_name}] NEW FILE DETECTED !!!")
            log.warning(f"  - {relative_path}")
            
            # --- v4 FEATURE: Active Response (Guardian) ---
            if self.mode == 'guardian':
                try:
                    os.remove(filepath)
                    log.info(f"  [GUARDIAN] Unauthorized file deleted: {relative_path}")
                except Exception as e:
                    log.error(f"  [GUARDIAN] FAILED to delete {relative_path}: {e}")

        elif event_type == "MODIFIED":
            new_hash = _hash_file(filepath)
            if new_hash and new_hash != original_hash:
                log.critical(f"!!! [Job: {self.job_name}] MODIFIED FILE DETECTED !!!")
                log.warning(f"  - {relative_path}")
                
                # --- v4 FEATURE: Active Response (Guardian) ---
                if self.mode == 'guardian' and original_hash: # Only heal known files
                    backup_file_path = os.path.join(self.job_backup_path, relative_path)
                    try:
                        shutil.copy(backup_file_path, filepath)
                        log.info(f"  [GUARDIAN] File restored from backup: {relative_path}")
                        # Update the debounce time again to prevent restore-loops
                        self.last_event_time[filepath] = time.time() 
                    except Exception as e:
                        log.error(f"  [GUARDIAN] FAILED to restore {relative_path}: {e}")

        elif event_type == "DELETED":
            if original_hash:
                log.critical(f"!!! [Job: {self.job_name}] DELETED FILE DETECTED !!!")
                log.warning(f"  - {relative_path} (File was in baseline)")
                
                # --- v4 FEATURE: Active Response (Guardian) ---
                if self.mode == 'guardian':
                    backup_file_path = os.path.join(self.job_backup_path, relative_path)
                    try:
                        shutil.copy(backup_file_path, filepath)
                        log.info(f"  [GUARDIAN] File restored from backup: {relative_path}")
                        self.last_event_time[filepath] = time.time()
                    except Exception as e:
                        log.error(f"  [GUARDIAN] FAILED to restore {relative_path}: {e}")
            else:
                log.info(f"--- [Job: {self.job_name}] Un-baselined file was deleted ---")
                log.info(f"  - {relative_path}")


def start_watching(job_name, job_config):
    """Starts the real-time watchdog observer."""
    
    path_to_monitor = job_config['path']
    log.info(f"--- [Job: {job_name}] Initializing Real-Time Watcher for: {path_to_monitor} ---")
    
    try:
        event_handler = FIMEventHandler(job_name, job_config)
        observer = Observer()
        observer.schedule(event_handler, path_to_monitor, recursive=True)
        observer.start()
        
        log.info(f"--- Watcher started. Press Ctrl+C to stop. ---")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            log.info(f"--- [Job: {job_name}] Watcher stopped. ---")
        observer.join()
        
    except Exception as e:
        log.error(f"Could not start watcher for job '{job_name}': {e}")


# --- Main Function (Refactored for Config File) ---

def main():
    """Main function to parse arguments and load config."""
    parser = argparse.ArgumentParser(
        description="Py-FIM v4 (Guardian Edition): A Real-Time File Integrity Monitor.",
        epilog="""
Example Usage:
  1. Create config.ini (see example).
  
  2. Create baseline for ALL jobs:
     python py_fim_v4.py --mode init --job ALL --force
     
  3. Check integrity of one job:
     python py_fim_v4.py --mode check --job MySecureFiles
     
  4. Start real-time "Guardian" monitoring:
     python py_fim_v4.py --mode watch --job MySecureFiles
"""
    , formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument(
        "--mode", 
        required=True, 
        choices=["init", "check", "watch"],
        help="Mode of operation: 'init', 'check', or 'watch'."
    )
    
    parser.add_argument(
        "--job",
        required=True,
        type=str,
        help="The Job Name from config.ini to run, or 'ALL' to run all jobs."
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force overwrite of an existing baseline during 'init' mode."
    )
    
    args = parser.parse_args()
    
    # --- Load Config File ---
    if not os.path.exists(CONFIG_FILE):
        log.error(f"Configuration file '{CONFIG_FILE}' not found.")
        log.error("Please create a 'config.ini' file.")
        return
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    # Get the default backup directory
    default_backup_dir = config.get('DEFAULT', 'backup_dir', fallback='.secure_backup')
    
    # Get the job(s) to run
    jobs_to_run = []
    if args.job.upper() == 'ALL':
        jobs_to_run = config.sections()
    else:
        if args.job not in config:
            log.error(f"Job '{args.job}' not found in {CONFIG_FILE}.")
            return
        jobs_to_run = [args.job]

    # Run the selected mode for the selected job(s)
    for job_name in jobs_to_run:
        try:
            job_config = {
                'path': os.path.abspath(config[job_name]['path']),
                'baseline_file': config[job_name]['baseline_file'],
                'ignore_patterns': [p.strip() for p in config[job_name].get('ignore', '').split(',') if p.strip()],
                'mode': config[job_name].get('mode', 'monitor'),
                'backup_dir': os.path.abspath(default_backup_dir),
                'backup_dir_name': os.path.basename(default_backup_dir),
            }
        except KeyError as e:
            log.error(f"Config error in job '{job_name}': Missing key {e}")
            continue
        
        if args.mode == "init":
            create_baseline(job_name, job_config, args.force)
        elif args.mode == "check":
            check_integrity(job_name, job_config)
        elif args.mode == "watch":
            if args.job.upper() == 'ALL':
                log.error("Cannot use 'watch' mode with 'ALL' jobs. Please select one job to watch.")
                break # Stop processing jobs
            start_watching(job_name, job_config)
            
if __name__ == "__main__":
    main()
