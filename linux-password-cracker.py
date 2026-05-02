#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import hashlib
import argparse
import os

# Renk kodları
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def detect_hash_type(hash_str):
    """Hash tipini otomatik tespit eder."""
    hash_str = hash_str.strip()
    
    # Linux Shadow Hashes
    if hash_str.startswith("$1$"):
        return "md5-crypt"
    elif hash_str.startswith("$5$"):
        return "sha256-crypt"
    elif hash_str.startswith("$6$"):
        return "sha512-crypt"
    elif hash_str.startswith("$2a$") or hash_str.startswith("$2b$") or hash_str.startswith("$2y$"):
        return "bcrypt"
    
    # Raw Hashes (Uzunluğa göre)
    if len(hash_str) == 32:
        return "md5"
    elif len(hash_str) == 40:
        return "sha1"
    elif len(hash_str) == 64:
        return "sha256"
    elif len(hash_str) == 128:
        return "sha512"
    
    return "unknown"

def crack_shadow_hash(target_hash, wordlist_path, hash_type):
    """Linux Shadow ($6$, $5$ vb.) hashlerini kırmak için passlib kullanır."""
    try:
        from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, bcrypt
    except ImportError:
        print(f"{Colors.FAIL}[!] Hata: 'passlib' kütüphanesi bulunamadı.{Colors.ENDC}")
        print(f"{Colors.WARNING}Lütfen 'pip install passlib' komutuyla yükleyin.{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.OKBLUE}[*] Shadow Hash Modu Başlatıldı: {hash_type}{Colors.ENDC}")
    
    mapper = {
        "md5-crypt": md5_crypt,
        "sha256-crypt": sha256_crypt,
        "sha512-crypt": sha512_crypt,
        "bcrypt": bcrypt
    }
    
    handler = mapper.get(hash_type)
    if not handler:
        print(f"{Colors.FAIL}[!] Desteklenmeyen shadow hash tipi: {hash_type}{Colors.ENDC}")
        return

    if not os.path.exists(wordlist_path):
        print(f"{Colors.FAIL}[!] Wordlist dosyası bulunamadı: {wordlist_path}{Colors.ENDC}")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                try:
                    if handler.verify(password, target_hash):
                        print(f"\n{Colors.OKGREEN}[+] ŞİFRE BULUNDU!{Colors.ENDC}")
                        print(f"{Colors.BOLD}Hash: {target_hash}{Colors.ENDC}")
                        print(f"{Colors.BOLD}Şifre: {password}{Colors.ENDC}")
                        return
                except Exception:
                    continue
                
                # İlerleme göstergesi (isteğe bağlı, çok yavaşlatabilir)
                # sys.stdout.write('.') 
                # sys.stdout.flush()

        print(f"\n{Colors.WARNING}[-] Şifre wordlist içinde bulunamadı.{Colors.ENDC}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] İşlem kullanıcı tarafından durduruldu.{Colors.ENDC}")

def crack_raw_hash(target_hash, wordlist_path, hash_type):
    """Ham (Raw) hashleri (örn: 169bd...) kırmak için hashlib kullanır."""
    print(f"{Colors.OKBLUE}[*] Raw Hash Modu Başlatıldı: {hash_type.upper()}{Colors.ENDC}")
    
    if not os.path.exists(wordlist_path):
        print(f"{Colors.FAIL}[!] Wordlist dosyası bulunamadı: {wordlist_path}{Colors.ENDC}")
        return

    hash_func_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    func = hash_func_map.get(hash_type)
    if not func:
        print(f"{Colors.FAIL}[!] Desteklenmeyen raw hash tipi: {hash_type}{Colors.ENDC}")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            count = 0
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                # Hash hesapla
                computed_hash = func(password.encode('utf-8')).hexdigest()
                
                if computed_hash == target_hash:
                    print(f"\n{Colors.OKGREEN}[+] ŞİFRE BULUNDU!{Colors.ENDC}")
                    print(f"{Colors.BOLD}Hash: {target_hash}{Colors.ENDC}")
                    print(f"{Colors.BOLD}Şifre: {password}{Colors.ENDC}")
                    return
                
                count += 1
                if count % 1000 == 0:
                    print(f"[*] {count} şifre denendi...", end='\r')

        print(f"\n{Colors.WARNING}[-] Şifre wordlist içinde bulunamadı. ({count} deneme){Colors.ENDC}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] İşlem kullanıcı tarafından durduruldu.{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description="Multi-Platform Password Cracker (Linux & Raw Hash)")
    parser.add_argument("-w", "--wordlist", help="Wordlist dosya yolu")
    parser.add_argument("-H", "--hash", help="Kırılacak hash değeri")
    parser.add_argument("-t", "--type", help="Hash tipi (manuel seçim için: sha512, sha256, md5, sha512-crypt vb.)", default=None)
    
    args = parser.parse_args()

    print(f"{Colors.HEADER}========================================")
    print(f"   Multi-Platform Password Cracker v2.1")
    print(f"   (Linux Shadow & Raw Hash Desteği + CLI)")
    print(f"========================================{Colors.ENDC}\n")

    target_hash = ""
    wordlist_path = ""
    force_type = args.type

    # Komut satırından gelen verileri kontrol et
    if args.hash:
        target_hash = args.hash.strip()
        print(f"{Colors.OKBLUE}[*] Hedef Hash (CLI): {target_hash[:20]}...{Colors.ENDC}")
    else:
        target_hash = input(f"{Colors.WARNING}Kırılacak hash'i yapıştırın: {Colors.ENDC}").strip()

    if args.wordlist:
        wordlist_path = args.wordlist
        print(f"{Colors.OKBLUE}[*] Wordlist Yolu (CLI): {wordlist_path}{Colors.ENDC}")
    else:
        wordlist_path = input(f"{Colors.WARNING}Wordlist dosya yolunu girin (örn: rockyou.txt): {Colors.ENDC}").strip()

    if not target_hash:
        print(f"{Colors.FAIL}[-] Hash girilmedi. Çıkılıyor.{Colors.ENDC}")
        sys.exit(1)
    
    if not wordlist_path:
        print(f"{Colors.FAIL}[-] Wordlist yolu girilmedi. Çıkılıyor.{Colors.ENDC}")
        sys.exit(1)

    # Hash tipini tespit et (veya manuel seçimi kullan)
    if force_type:
        hash_type = force_type
        print(f"{Colors.WARNING}[!] Manuel hash tipi seçildi: {hash_type}{Colors.ENDC}")
    else:
        hash_type = detect_hash_type(target_hash)
        print(f"{Colors.OKGREEN}[+] Tespit edilen hash tipi: {hash_type}{Colors.ENDC}")

    if hash_type == "unknown":
        print(f"{Colors.FAIL}[!] Hash tipi tanınamadı. Lütfen -t parametresi ile manuel belirtin (örn: -t sha512){Colors.ENDC}")
        sys.exit(1)

    # Kırma işlemine başla
    if hash_type in ["md5-crypt", "sha256-crypt", "sha512-crypt", "bcrypt"]:
        crack_shadow_hash(target_hash, wordlist_path, hash_type)
    elif hash_type in ["md5", "sha1", "sha256", "sha512"]:
        crack_raw_hash(target_hash, wordlist_path, hash_type)
    else:
        print(f"{Colors.FAIL}[!] Bu hash tipi için kırma modülü bulunamadı.{Colors.ENDC}")

if __name__ == "__main__":
    main()
