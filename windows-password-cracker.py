import hashlib
import binascii
import sys
import threading
import time

def ntlm_hash(password):
    """Windows NTLM Hash üretici."""
    # Windows şifreleri UTF-16LE olarak encode eder ve MD4 ile hashler
    hash_obj = hashlib.new('md4', password.encode('utf-16le'))
    return binascii.hexlify(hash_obj.digest()).decode().upper()

class Cracker:
    def __init__(self, target_hash, wordlist_path):
        self.target_hash = target_hash.upper()
        self.wordlist_path = wordlist_path
        self.found = False
        self.password = None

    def attempt_crack(self, chunk):
        for word in chunk:
            if self.found:
                return
            word = word.strip()
            if ntlm_hash(word) == self.target_hash:
                self.found = True
                self.password = word
                return

def main():
    print("-" * 50)
    print("   Windows NTLM Password Cracker - Educational PoC")
    print("-" * 50)

    # Örnek kullanım: python windows-password-cracker.py <hash> <wordlist>
    if len(sys.argv) < 3:
        print("[!] Usage: python windows-password-cracker.py <NTLM_HASH> <WORDLIST_PATH>")
        sys.exit(1)

    target_hash = sys.argv[1]
    wordlist_file = sys.argv[2]

    try:
        with open(wordlist_file, 'r', encoding='latin-1') as f:
            words = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: {wordlist_file} not found.")
        sys.exit(1)

    print(f"[*] Target Hash: {target_hash}")
    print(f"[*] Loaded {len(words)} passwords.")
    print("[*] Cracking... Please wait.")

    start_time = time.time()
    
    # Kelime listesini iş parçacıklarına bölme (Multi-threading)
    num_threads = 4
    chunk_size = len(words) // num_threads
    threads = []
    cracker = Cracker(target_hash, wordlist_file)

    for i in range(num_threads):
        chunk = words[i*chunk_size : (i+1)*chunk_size]
        t = threading.Thread(target=cracker.attempt_crack, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = time.time()

    if cracker.found:
        print(f"\n[+] SUCCESS!")
        print(f"[+] Password Found: {cracker.password}")
    else:
        print("\n[-] Password not found in wordlist.")

    print(f"[*] Time taken: {round(end_time - start_time, 2)} seconds")

if __name__ == "__main__":
    main()
