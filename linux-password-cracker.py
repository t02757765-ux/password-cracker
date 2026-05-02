#!/usr/bin/env python3
"""
Linux Password Hash Cracker
Supports common Linux hash types: MD5-Crypt, SHA-256-Crypt, SHA-512-Crypt
Uses John the Ripper or Hashcat backends with automatic hash detection
"""

import hashlib
import crypt
import re
import sys
import os
import argparse
from pathlib import Path
from typing import Optional, Tuple, List

class LinuxPasswordCracker:
    """Linux password hash cracker with multiple algorithm support"""
    
    # Hash type patterns for automatic detection
    HASH_PATTERNS = {
        'MD5-Crypt': r'^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$',
        'SHA-256-Crypt': r'^\$5\$(rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43}$',
        'SHA-512-Crypt': r'^\$6\$(rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}$',
        'DES-Crypt': r'^[a-zA-Z0-9./]{2}[a-zA-Z0-9./]{11}$',
        'Blowfish': r'^\$2[aby]?\$[0-9]{2}\$[a-zA-Z0-9./]{22}\$[a-zA-Z0-9./]{31}$',
    }
    
    def __init__(self, wordlist_path: str = None):
        """Initialize the cracker with optional wordlist"""
        self.wordlist_path = wordlist_path
        self.supported_hashes = list(self.HASH_PATTERNS.keys())
        
    def detect_hash_type(self, hash_string: str) -> Optional[str]:
        """Automatically detect the hash type from the hash string"""
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if re.match(pattern, hash_string):
                return hash_type
        return None
    
    def crack_with_wordlist(self, hash_string: str, wordlist: str = None) -> Tuple[bool, str]:
        """
        Crack password using wordlist attack
        Returns (success, password_or_error)
        """
        if wordlist is None:
            wordlist = self.wordlist_path
            
        if not wordlist or not os.path.exists(wordlist):
            return False, "Wordlist file not found"
        
        hash_type = self.detect_hash_type(hash_string)
        if not hash_type:
            return False, "Unknown hash type"
        
        print(f"[*] Detected hash type: {hash_type}")
        print(f"[*] Starting wordlist attack with: {wordlist}")
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, password in enumerate(f, 1):
                    password = password.strip()
                    if not password:
                        continue
                    
                    # Try to verify the password
                    if self.verify_password(password, hash_string):
                        print(f"[+] Password found: {password}")
                        print(f"[+] Found after {line_num} attempts")
                        return True, password
                    
                    # Progress indicator every 10000 passwords
                    if line_num % 10000 == 0:
                        print(f"[*] Tested {line_num} passwords...")
                        
        except Exception as e:
            return False, f"Error reading wordlist: {str(e)}"
        
        return False, "Password not found in wordlist"
    
    def verify_password(self, password: str, hash_string: str) -> bool:
        """Verify if a password matches the given hash"""
        try:
            # Python's crypt.crypt() handles all Linux hash types automatically
            computed_hash = crypt.crypt(password, hash_string)
            return computed_hash == hash_string
        except Exception:
            return False
    
    def generate_test_hash(self, password: str, hash_type: str = 'SHA-512-Crypt') -> str:
        """Generate a test hash for demonstration purposes"""
        import random
        import string
        
        # Generate random salt
        salt_chars = string.ascii_letters + string.digits + './'
        salt_length = 16 if hash_type in ['SHA-256-Crypt', 'SHA-512-Crypt'] else 8
        
        if hash_type == 'MD5-Crypt':
            salt = '$1$' + ''.join(random.choice(salt_chars) for _ in range(8))
        elif hash_type == 'SHA-256-Crypt':
            salt = '$5$' + ''.join(random.choice(salt_chars) for _ in range(16))
        elif hash_type == 'SHA-512-Crypt':
            salt = '$6$' + ''.join(random.choice(salt_chars) for _ in range(16))
        elif hash_type == 'DES-Crypt':
            salt = ''.join(random.choice(salt_chars) for _ in range(2))
        elif hash_type == 'Blowfish':
            salt = '$2y$12$' + ''.join(random.choice(salt_chars) for _ in range(22))
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        return crypt.crypt(password, salt)
    
    def brute_force_attack(self, hash_string: str, charset: str = None, 
                          max_length: int = 8) -> Tuple[bool, str]:
        """
        Simple brute force attack (use with caution - can be very slow)
        """
        if charset is None:
            charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
        
        hash_type = self.detect_hash_type(hash_string)
        if not hash_type:
            return False, "Unknown hash type"
        
        print(f"[*] Starting brute force attack on {hash_type} hash")
        print(f"[*] Character set: {charset}")
        print(f"[*] Max length: {max_length}")
        
        from itertools import product
        
        attempts = 0
        for length in range(1, max_length + 1):
            for candidate in product(charset, repeat=length):
                password = ''.join(candidate)
                attempts += 1
                
                if self.verify_password(password, hash_string):
                    print(f"[+] Password found: {password}")
                    print(f"[+] Found after {attempts} attempts")
                    return True, password
                
                if attempts % 100000 == 0:
                    print(f"[*] Tested {attempts} combinations...")
        
        return False, f"Password not found (tested {attempts} combinations)"


def main():
    parser = argparse.ArgumentParser(
        description='Linux Password Hash Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -h "HASH_STRING" -w /path/to/wordlist.txt
  %(prog)s --hash "HASH_STRING" --wordlist rockyou.txt
  %(prog)s --generate-test "mypassword" --hash-type SHA-512-Crypt
  %(prog)s -h "HASH_STRING" --brute-force --charset abc123 --max-length 6
        """
    )
    
    parser.add_argument('-H', '--hash', dest='hash_string', 
                       help='Target hash to crack')
    parser.add_argument('-w', '--wordlist', dest='wordlist',
                       help='Path to wordlist file')
    parser.add_argument('-t', '--hash-type', dest='hash_type',
                       choices=['MD5-Crypt', 'SHA-256-Crypt', 'SHA-512-Crypt', 
                               'DES-Crypt', 'Blowfish'],
                       help='Hash type (auto-detected if not specified)')
    parser.add_argument('--generate-test', dest='generate_test',
                       help='Generate a test hash for the given password')
    parser.add_argument('--brute-force', action='store_true',
                       help='Use brute force attack instead of wordlist')
    parser.add_argument('--charset', default='abcdefghijklmnopqrstuvwxyz0123456789',
                       help='Character set for brute force (default: lowercase+digits)')
    parser.add_argument('--max-length', type=int, default=6,
                       help='Maximum password length for brute force (default: 6)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    cracker = LinuxPasswordCracker(args.wordlist)
    
    # Generate test hash if requested
    if args.generate_test:
        hash_type = args.hash_type or 'SHA-512-Crypt'
        test_hash = cracker.generate_test_hash(args.generate_test, hash_type)
        print(f"Generated {hash_type} hash for '{args.generate_test}':")
        print(test_hash)
        return
    
    if not args.hash_string:
        parser.print_help()
        print("\nError: Please provide a hash to crack (-H/--hash)")
        sys.exit(1)
    
    # Auto-detect hash type
    detected_type = cracker.detect_hash_type(args.hash_string)
    if not detected_type:
        print("Error: Could not detect hash type")
        print("Supported types:", ', '.join(cracker.supported_hashes))
        sys.exit(1)
    
    print(f"[*] Target hash: {args.hash_string}")
    print(f"[*] Detected type: {detected_type}")
    
    if args.brute_force:
        success, result = cracker.brute_force_attack(
            args.hash_string, 
            args.charset, 
            args.max_length
        )
    else:
        if not args.wordlist:
            print("Error: Please provide a wordlist (-w/--wordlist) or use --brute-force")
            sys.exit(1)
        success, result = cracker.crack_with_wordlist(args.hash_string)
    
    if success:
        print(f"\n[SUCCESS] Password cracked: {result}")
        sys.exit(0)
    else:
        print(f"\n[FAILED] {result}")
        sys.exit(1)


if __name__ == '__main__':
    main()
