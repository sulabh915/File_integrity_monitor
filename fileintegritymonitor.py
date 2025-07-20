import hashlib
import os
import time

# Function to calculate hash of a file
def calculate_hash(file_path, algo='sha256'):
    try:
        hash_func = hashlib.new(algo)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"[!] Error hashing {file_path}: {e}")
        return None

# Function to monitor files in a directory
def monitor_directory(directory, algo='sha256', interval=10):
    print(f"[*] Monitoring changes in: {directory} (Algorithm: {algo})")
    previous_hashes = {}

    while True:
        current_hashes = {}

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path, algo)
                if file_hash:
                    current_hashes[file_path] = file_hash

        # Compare with previous state
        for path, new_hash in current_hashes.items():
            if path not in previous_hashes:
                print(f"[+] New file detected: {path}")
            elif previous_hashes[path] != new_hash:
                print(f"[*] File modified: {path}")

        for path in previous_hashes:
            if path not in current_hashes:
                print(f"[-] File deleted: {path}")

        previous_hashes = current_hashes
        time.sleep(interval)

def main():
    directory = input("Enter directory to monitor: ").strip()
    interval = input("Enter monitoring interval (seconds): ").strip()
    algo = input("Enter hashing algorithm (default: sha256): ").strip().lower()
    algo = algo if algo else 'sha256'

    if not os.path.isdir(directory):
        print("[!] Invalid directory path.")
        return

    try:
        interval = int(interval)
    except ValueError:
        interval = 10

    monitor_directory(directory, algo, interval)

if __name__ == '__main__':
    main()
