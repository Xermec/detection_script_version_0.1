#!/usr/bin/python3
import os
import pwd
import stat
import pyinotify
import psutil 
import time


SCAN_PATHS = ['/tmp', '/var/tmp', '/dev/shm', '/home']
WATCH_PATHS = {
    os.path.realpath('/etc'): 'PERSISTENCE: Critical system directory modified',
    os.path.realpath('/tmp'): 'DROPPER: File activity in /tmp',
    os.path.realpath('/var/tmp'): 'DROPPER: File activity in /var/tmp',
    os.path.realpath('/dev/shm'): 'DROPPER: File activity in shared memory',
    os.path.realpath('/home'): 'PERSISTENCE: Activity in user home directories'
}

SUSPICIOUS_PARENT_CHILD_MAP = {
    'apache2': ['sh', 'bash', 'zsh', 'curl', 'wget', 'python', 'perl'],
    'nginx':   ['sh', 'bash', 'zsh', 'curl', 'wget', 'python', 'perl'],
    'httpd':   ['sh', 'bash', 'zsh', 'curl', 'wget', 'python', 'perl'], 
    'cron':    ['sh', 'bash', 'zsh', 'curl', 'wget'],
    'systemd': ['sh', 'bash'] 
}


reported_processes = set()


def quarantine_file(filepath):
    try:
        print(f"  -> [ACTION] Quarantining file: {filepath}")
        os.chmod(filepath, 0o000)
    except Exception as e:
        print(f"  -> [ERROR] Failed to quarantine {filepath}: {e}")


def run_initial_scan():
    print("[+] Running Initial Baseline Scan...")
    
    for path in SCAN_PATHS:
        if not os.path.exists(path): continue
        for root, _, files in os.walk(path):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    mode = os.stat(filepath).st_mode
                    if (mode & stat.S_IXUSR):
                        print(f"\n--- [!!!] INITIAL SCAN: EXECUTABLE DROPPER DETECTED [!!!] ---")
                        print(f"  -> File: {filepath}")
                        quarantine_file(filepath)
                        print(f"-------------------------------------------------")
                except (FileNotFoundError, PermissionError):
                    continue

    
    print("[+] Scanning for known persistence mechanisms...")
    persistence_locations = {'/etc/rc.local': 'rc.local modification'}
    for user in pwd.getpwall():
        if user.pw_dir.startswith('/home/'):
            persistence_locations[os.path.join(user.pw_dir, '.bashrc')] = f"{user.pw_name}'s bashrc modification"

    for p_file, desc in persistence_locations.items():
        if os.path.exists(p_file):
            with open(p_file, 'r') as f:
                for line in f:
                    
                    if any(s in line for s in ['/tmp/', '/var/tmp/', '/dev/shm/']) and any(c in line for c in ['sh', 'python', 'perl']):
                        print(f"\n--- [!!!] INITIAL SCAN: SUSPICIOUS PERSISTENCE DETECTED [!!!] ---")
                        print(f"  -> Description: {desc}")
                        print(f"  -> File: {p_file}")
                        print(f"  -> Suspicious Line: {line.strip()}")
                        print(f"-------------------------------------------------")
    print("[+] Initial Scan finished.\n")



def detect_process_ancestry_anomalies():
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'connections']):
        try:
            pid = proc.info['pid']
            if pid in reported_processes:
                continue
            
            
            parent = proc.parent()
            if parent is None:
                continue
            
            p_name = parent.name()
            c_name = proc.name()

            
            if p_name in SUSPICIOUS_PARENT_CHILD_MAP and c_name in SUSPICIOUS_PARENT_CHILD_MAP[p_name]:
                
                connections = proc.info.get('connections', [])
                if any(conn.status == 'ESTABLISHED' for conn in connections):
                    print(f"\n--- [!!!] PROCESS ANCESTRY ANOMALY DETECTED [!!!] ---")
                    print(f"  -> Threat Type: Suspicious child process with network activity (Reverse Shell?).")
                    print(f"  -> Parent Process: '{p_name}' (PID: {parent.pid})")
                    print(f"  -> Child Process:  '{c_name}' (PID: {pid})")
                    print(f"-------------------------------------------------")
                    reported_processes.add(pid)
                        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


class EventHandler(pyinotify.ProcessEvent):
    def process_default(self, event):
        for path_prefix, threat_type in WATCH_PATHS.items():
            if event.pathname.startswith(path_prefix):
                print(f"\n--- [!!!] REAL-TIME: FILE SYSTEM ACTIVITY [!!!] ---")
                print(f"  -> Threat Type Guess: {threat_type}")
                print(f"  -> Event: '{event.maskname}' on '{event.pathname}'")
                
                
                if 'DROPPER' in threat_type and 'IN_CREATE' in event.maskname:
                    try:
                        mode = os.stat(event.pathname).st_mode
                        if (mode & stat.S_IXUSR):
                            print(f"  -> Executable file created. Taking action.")
                            quarantine_file(event.pathname)
                    except (FileNotFoundError, PermissionError):
                        pass 
                print(f"-------------------------------------------------")
                break 


if __name__ == "__main__":
    
    run_initial_scan()

    print("[+] Starting Real-time EDR Engine (File System + Process Monitoring)...")
    
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_DELETE
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)

    for path in WATCH_PATHS.keys():
        if os.path.exists(path):
            wm.add_watch(path, mask, rec=True, auto_add=True)
            print(f"  -> Watching: {path} and its subdirectories")

    
    while True:
        try:
            
            detect_process_ancestry_anomalies()
            
            
            if notifier.check_events(timeout=0):
                notifier.read_events()
                notifier.process_events()

            
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\nShutting down EDR engine.")
            notifier.stop()
            break
        except Exception as e:
            
            print(f"\n[ERROR] An unexpected error occurred: {e}")
            time.sleep(10)
