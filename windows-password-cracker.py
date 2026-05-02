import hashlib
import binascii
import sys
import threading
import time
import crypt
import re

def ntlm_hash(password):
    """Windows NTLM Hash üretici."""
    # Windows şifreleri UTF-16LE olarak encode eder ve MD4 ile hashler
    hash_obj = hashlib.new('md4', password.encode('utf-16le'))
    return binascii.hexlify(hash_obj.digest()).decode().upper()

def md5_hash(password):
    """Düz MD5 hash (bazı eski sistemlerde kullanılır)."""
    return hashlib.md5(password.encode()).hexdigest()

def sha1_hash(password):
    """SHA-1 hash."""
    return hashlib.sha1(password.encode()).hexdigest()

def sha256_hash(password):
    """SHA-256 hash."""
    return hashlib.sha256(password.encode()).hexdigest()

def sha512_hash(password):
    """SHA-512 hash."""
    return hashlib.sha512(password.encode()).hexdigest()

def md5_crypt(password, salt=None):
    """Linux MD5 Crypt ($1$)."""
    if salt is None:
        salt = "$1$" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    elif not salt.startswith("$1$"):
        salt = "$1$" + salt
    return crypt.crypt(password, salt)

def sha256_crypt(password, salt=None):
    """Linux SHA-256 Crypt ($5$)."""
    if salt is None:
        salt = "$5$" + hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    elif not salt.startswith("$5$"):
        salt = "$5$" + salt
    return crypt.crypt(password, salt)

def sha512_crypt(password, salt=None):
    """Linux SHA-512 Crypt ($6$)."""
    if salt is None:
        salt = "$6$" + hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    elif not salt.startswith("$6$"):
        salt = "$6$" + salt
    return crypt.crypt(password, salt)

def detect_hash_type(hash_string):
    """Hash tipini otomatik algıla."""
    hash_string = hash_string.strip()
    
    # Windows NTLM (32 karakter hex)
    if re.match(r'^[A-Fa-f0-9]{32}$', hash_string):
        # NTLM veya MD5 olabilir, bağlama göre karar verilir
        return 'NTLM/MD5'
    
    # SHA-1 (40 karakter hex)
    if re.match(r'^[A-Fa-f0-9]{40}$', hash_string):
        return 'SHA-1'
    
    # SHA-256 (64 karakter hex)
    if re.match(r'^[A-Fa-f0-9]{64}$', hash_string):
        return 'SHA-256'
    
    # SHA-512 (128 karakter hex)
    if re.match(r'^[A-Fa-f0-9]{128}$', hash_string):
        return 'SHA-512'
    
    # MD5 Crypt ($1$)
    if hash_string.startswith('$1$'):
        return 'MD5-CRYPT'
    
    # SHA-256 Crypt ($5$)
    if hash_string.startswith('$5$'):
        return 'SHA256-CRYPT'
    
    # SHA-512 Crypt ($6$)
    if hash_string.startswith('$6$'):
        return 'SHA512-CRYPT'
    
    # bcrypt ($2a$, $2b$, $2y$)
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or hash_string.startswith('$2y$'):
        return 'BCRYPT'
    
    # Argon2 ($argon2id$, $argon2i$, $argon2d$)
    if hash_string.startswith('$argon2'):
        return 'ARGON2'
    
    # PBKDF2 (macOS)
    if hash_string.startswith('$pbkdf2'):
        return 'PBKDF2'
    
    return 'UNKNOWN'

class Cracker:
    def __init__(self, target_hash, wordlist_path, hash_type='auto'):
        self.target_hash = target_hash.strip()
        self.wordlist_path = wordlist_path
        self.found = False
        self.password = None
        
        # Hash tipini belirle
        if hash_type == 'auto':
            self.hash_type = detect_hash_type(target_hash)
        else:
            self.hash_type = hash_type.upper()
        
        # Hash fonksiyonunu seç
        self.hash_functions = {
            'NTLM': ntlm_hash,
            'MD5': md5_hash,
            'SHA-1': sha1_hash,
            'SHA-256': sha256_hash,
            'SHA-512': sha512_hash,
            'MD5-CRYPT': lambda p: md5_crypt(p, self.target_hash.split('$')[2] if len(self.target_hash.split('$')) > 2 else None),
            'SHA256-CRYPT': lambda p: sha256_crypt(p, self.target_hash.split('$')[2] if len(self.target_hash.split('$')) > 2 else None),
            'SHA512-CRYPT': lambda p: sha512_crypt(p, self.target_hash.split('$')[2] if len(self.target_hash.split('$')) > 2 else None),
        }
        
        if self.hash_type in ['NTLM/MD5']:
            # Hem NTLM hem MD5 dene
            self.hash_functions['NTLM/MD5'] = None  # Özel işlem

    def attempt_crack(self, chunk):
        for word in chunk:
            if self.found:
                return
            word = word.strip()
            
            if self.hash_type == 'NTLM/MD5':
                # Önce NTLM dene
                if ntlm_hash(word) == self.target_hash.upper():
                    self.found = True
                    self.password = word
                    self.detected_type = 'NTLM'
                    return
                # Sonra MD5 dene
                if md5_hash(word) == self.target_hash.lower():
                    self.found = True
                    self.password = word
                    self.detected_type = 'MD5'
                    return
            
            elif self.hash_type in ['MD5-CRYPT', 'SHA256-CRYPT', 'SHA512-CRYPT']:
                # Linux crypt formatları için
                if self.hash_functions.get(self.hash_type)(word) == self.target_hash:
                    self.found = True
                    self.password = word
                    return
            
            elif self.hash_type in self.hash_functions:
                if self.hash_functions[self.hash_type](word) == self.target_hash:
                    self.found = True
                    self.password = word
                    return

def main():
    print("=" * 70)
    print("   Multi-Platform Password Cracker - Educational PoC")
    print("   Windows, Linux, macOS & Unix Sistemler İçin")
    print("=" * 70)
    print("\nDesteklenen Hash Tipleri:")
    print("  • Windows: NTLM")
    print("  • Linux/Unix: MD5-Crypt ($1$), SHA-256-Crypt ($5$), SHA-512-Crypt ($6$)")
    print("  • Genel: MD5, SHA-1, SHA-256, SHA-512")
    print("  • Not: bcrypt ve Argon2 için özel kütüphaneler gerekir")
    print("-" * 70)

    # Örnek kullanım
    if len(sys.argv) < 3:
        print("\n[!] Usage: python multi-password-cracker.py <HASH> <WORDLIST_PATH> [HASH_TYPE]")
        print("\nÖrnekler:")
        print("  python multi-password-cracker.py 8846f7eaee8fb117ad06bdd830b7586c wordlist.txt")
        print("  python multi-password-cracker.py '$6$salt$hash...' wordlist.txt")
        print("  python multi-password-cracker.py <hash> wordlist.txt NTLM")
        print("  python multi-password-cracker.py <hash> wordlist.txt SHA-512")
        sys.exit(1)

    target_hash = sys.argv[1]
    wordlist_file = sys.argv[2]
    hash_type = sys.argv[3] if len(sys.argv) > 3 else 'auto'

    try:
        with open(wordlist_file, 'r', encoding='latin-1') as f:
            words = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: {wordlist_file} not found.")
        sys.exit(1)

    detected = detect_hash_type(target_hash)
    print(f"\n[*] Target Hash: {target_hash}")
    print(f"[*] Detected Type: {detected}")
    if hash_type != 'auto':
        print(f"[*] Forced Type: {hash_type}")
    print(f"[*] Loaded {len(words)} passwords.")
    print("[*] Cracking... Please wait.\n")

    start_time = time.time()
    
    # Kelime listesini iş parçacıklarına bölme (Multi-threading)
    num_threads = 4
    chunk_size = len(words) // num_threads
    threads = []
    cracker = Cracker(target_hash, wordlist_file, hash_type)

    for i in range(num_threads):
        chunk = words[i*chunk_size : (i+1)*chunk_size]
        t = threading.Thread(target=cracker.attempt_crack, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = time.time()

    if cracker.found:
        print(f"\n{'='*70}")
        print(f"[+] SUCCESS!")
        print(f"[+] Password Found: {cracker.password}")
        if hasattr(cracker, 'detected_type'):
            print(f"[+] Hash Type: {cracker.detected_type}")
        else:
            print(f"[+] Hash Type: {cracker.hash_type}")
        print(f"{'='*70}")
    else:
        print("\n[-] Password not found in wordlist.")

    print(f"[*] Time taken: {round(end_time - start_time, 2)} seconds")

if __name__ == "__main__":
    main()
