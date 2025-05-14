import os
import csv
import time
import threading

# Patterns for sensitive information
SENSITIVE_KEYWORDS = [
    "password", "secret", "credentials", "token", ".env", "id_rsa", "config.json", "key.pem"
]

# Common antivirus products by name or folder
ANTIVIRUS_KEYWORDS = [
    "Windows Defender", "Norton", "Kaspersky", "McAfee", "Bitdefender",
    "Avast", "AVG", "ESET", "Malwarebytes", "Sophos", "Trend Micro", "Defender"
]

# Exclude folders to avoid permission issues or slow scans
EXCLUDED_DIRS = [
    "C:\\Windows", "C:\\ProgramData", "/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run"
]

# Output CSV file
CSV_OUTPUT = "system_scan_report.csv"

# Global results list and lock
results_lock = threading.Lock()
results = []

def is_sensitive_file(filename):
    return any(keyword.lower() in filename.lower() for keyword in SENSITIVE_KEYWORDS)

def is_antivirus_related(path):
    components = [part.lower() for part in os.path.normpath(path).split(os.sep)]
    return any(av.lower() in components for av in [a.lower() for a in ANTIVIRUS_KEYWORDS])

def should_skip_dir(path):
    return any(path.lower().startswith(skip.lower()) for skip in EXCLUDED_DIRS)

def scan_directory(directory):
    try:
        with os.scandir(directory) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if not should_skip_dir(entry.path):
                            scan_directory(entry.path)  # Recurse into subdirectories
                    elif entry.is_file(follow_symlinks=False):
                        if is_sensitive_file(entry.name):
                            with results_lock:
                                results.append((entry.path, "Sensitive", "Matched keyword"))
                        elif is_antivirus_related(entry.path):
                            with results_lock:
                                results.append((entry.path, "Antivirus", "Matched AV keyword"))
                except (PermissionError, FileNotFoundError):
                    continue
    except (PermissionError, FileNotFoundError):
        pass  # Skip unreadable directories

def write_csv(data):
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["File Path", "Category", "Note"])
        writer.writerows(data)

def main():
    print("Scanning for sensitive files and antivirus traces...")
    start_time = time.time()

    # Starting points (choose appropriate one for your OS)
    directories_to_scan = []

    if os.name == "nt":  # Windows
        directories_to_scan = ["C:\\"]
    else:  # Unix/Linux/Mac
        directories_to_scan = ["/"]

    threads = []
    for directory in directories_to_scan:
        thread = threading.Thread(target=scan_directory, args=(directory,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    write_csv(results)
    print(f"Scan completed. Found {len(results)} matches.")
    print(f"Results saved to {CSV_OUTPUT}")
    print(f"Duration: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
