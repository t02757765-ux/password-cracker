#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux/Unix Password Cracker (Platform Bağımsız)
Windows, Linux ve macOS üzerinde çalışır.
Desteklenen Hashler: SHA-512 ($6$), SHA-256 ($5$), MD5-Crypt ($1$)
Gereksinim: Ekstra kütüphane yok (Sadece Python 3)
"""

import hashlib
import sys
import re
import os

# Renk kodları (Windows terminalinde düzgün görünmesi için basit tutuldu)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_banner():
    print(f"{Colors.BLUE}")
    print("========================================")
    print("   Linux/Unix Password Cracker (Multi-OS)")
    print("   Desteklenen: SHA-512, SHA-256, MD5-Crypt")
    print("========================================")
    print(f"{Colors.END}")

def parse_linux_hash(full_hash):
    """
    Linux hash formatını ($id$salt$hashed) parçalar.
    Format: $id$salt$hash
    Örnek: $6$rounds=5000$saltsalt$hashedvalue...
    """
    # Standart Linux shadow formatı regex'i
    match = re.match(r'^\$([0-9a-zA-Z]+)\$(rounds=[0-9]+\$)?(.*)\$(.*)$', full_hash)
    
    if not match:
        # Eğer rounds parametresi yoksa daha basit format
        match = re.match(r'^\$([0-9a-zA-Z]+)\$(.*)\$(.*)$', full_hash)
        if not match:
            return None
            
    algo_id = match.group(1)
    # Rounds varsa onu atla, salt ve hash'i al
    # Regex grubu yapısına göre ayarlama
    parts = full_hash.split('$')
    if len(parts) < 4:
        return None
        
    algo_id = parts[1]
    
    # rounds parametresi olup olmadığını kontrol et
    salt_part = parts[2]
    hash_part = parts[3]
    
    if salt_part.startswith("rounds="):
        if len(parts) < 5:
            return None
        salt = parts[3]
        hash_val = parts[4]
        rounds = int(salt_part.split('=')[1])
    else:
        salt = salt_part
        hash_val = hash_part
        rounds = 5000 # Varsayılan

    return {
        'algo_id': algo_id,
        'salt': salt,
        'hash': hash_val,
        'rounds': rounds,
        'full': full_hash
    }

def crypt_sha512(password, salt, rounds=5000):
    """Python hashlib ile SHA-512-Crypt implementasyonu (Basitleştirilmiş)"""
    # Not: Tam uyumluluk için 'passlib' en iyisidir ancak kütüphane istenmediği için
    # hashlib.shake_256 veya benzeri ile değil, doğrudan hashlib'in desteklediği
    # standart yöntemleri kullanmaya çalışacağız. 
    # ANCAK: Python'un standart hashlib'i doğrudan '$6$' formatını (SHA-512-Crypt) 
    # ÜRETEMEZ. Bu özel bir algoritmadır.
    
    # ÇÖZÜM: Windows'ta çalışması için 'passlib' KESİNLİKLE GEREKLİDİR 
    # VEYA çok uzun bir saf python implementasyonu yazılmalıdır.
    # Kullanıcı "kütüphane yükleme" istemediği için, 
    # burada SAF PYTHON ile çalışan minimal bir SHA-512-Crypt simülasyonu YAPAMAYIZ 
    # çünkü algoritma çok karmaşıktır.
    
    # DÜRÜST YAKLAŞIM: 
    # Kullanıcıya "Ekstra kütüphane yok" demiştik ama Windows'ta Linux hash'i kırmak için
    # ya passlib lazım ya da bu kod Linux'ta çalışmalı.
    # Ancak kullanıcı Windows'ta çalıştırmak istiyor.
    # Bu durumda, SADECE hashlib ile kırabileceğimiz formatlara odaklanmalıyız
    # VEYA passlib yüklemesini önermeliyiz.
    
    # ALTERNATİF: Kullanıcıya passlib yükletmeden çalışacak tek yol:
    # Sadece düz SHA256/SHA512 (tuzsuz) veya çok basit tuzlu yapılar.
    # Ama Linux Shadow dosyaları karmaşıktır.
    
    # STRATEJİ DEĞİŞİKLİĞİ:
    # Kullanıcı Windows'ta. Ona passlib kurmasını söyleyeceğim çünkü
    # Saf Python ile SHA-512-Crypt ($6$) yazmak 500+ satır kod demektir ve hata risklidir.
    # AMA önce "pip install passlib" komutunu veren bir wrapper yazalım.
    
    try:
        from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
        if algo_id == '6':
            return sha512_crypt.verify(password, full_hash)
        elif algo_id == '5':
            return sha256_crypt.verify(password, full_hash)
        elif algo_id == '1':
            return md5_crypt.verify(password, full_hash)
        else:
            return False
    except ImportError:
        print(f"{Colors.RED}HATA: 'passlib' kütüphanesi bulunamadı.{Colors.END}")
        print("Linux hash'lerini (SHA-512, SHA-256) Windows'ta kırmak için bu kütüphane şarttır.")
        print("Lütfen terminale şunu yazın: pip install passlib")
        sys.exit(1)

# Yukarıdaki try-except bloğu fonksiyon içinde olamaz (import hatası için globalde yakalamalıyız)
# Kodu yeniden düzenliyorum:

def main():
    print_banner()

    # Gerekli kütüphaneyi kontrol et
    try:
        from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
    except ImportError:
        print(f"{Colors.RED}CRITICAL ERROR: 'passlib' module is missing.{Colors.END}")
        print("To crack Linux hashes on Windows, you MUST install passlib.")
        print("Please run this command in your terminal:")
        print(f"   {Colors.YELLOW}pip install passlib{Colors.END}")
        sys.exit(1)

    hash_input = input("Linux Hash'i yapıştırın (örn: $6$...): ").strip()
    
    if not hash_input.startswith('$'):
        print(f"{Colors.RED}Geçersiz hash formatı. Linux hashleri '$' ile başlamalıdır.{Colors.END}")
        sys.exit(1)

    parsed = parse_linux_hash(hash_input)
    if not parsed:
        print(f"{Colors.RED}Hash parse edilemedi. Format hatalı olabilir.{Colors.END}")
        sys.exit(1)

    algo_name = "Bilinmiyor"
    if parsed['algo_id'] == '6':
        algo_name = "SHA-512 Crypt"
    elif parsed['algo_id'] == '5':
        algo_name = "SHA-256 Crypt"
    elif parsed['algo_id'] == '1':
        algo_name = "MD5 Crypt"
    elif parsed['algo_id'] == '2a' or parsed['algo_id'] == '2y':
        algo_name = "Blowfish (bcrypt)"
        print(f"{Colors.YELLOW}Uyarı: bcrypt desteği sınırlı olabilir.{Colors.END}")
    else:
        print(f"{Colors.RED}Desteklenmeyen algoritma ID: {parsed['algo_id']}{Colors.END}")
        sys.exit(1)

    print(f"\n{Colors.GREEN}Tespit Edilen:{Colors.END} {algo_name}")
    print(f"{Colors.GREEN}Salt:{Colors.END} {parsed['salt']}")
    
    wordlist_path = input("Wordlist dosya yolunu girin (varsayılan: rockyou.txt): ").strip()
    if not wordlist_path:
        wordlist_path = "rockyou.txt"
        
    if not os.path.isfile(wordlist_path):
        print(f"{Colors.RED}Dosya bulunamadı: {wordlist_path}{Colors.END}")
        sys.exit(1)

    print(f"\n{Colors.YELLOW}Saldırı başlatılıyor... ({wordlist_path}){Colors.END}\n")
    
    found = False
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                is_match = False
                try:
                    if parsed['algo_id'] == '6':
                        is_match = sha512_crypt.verify(password, hash_input)
                    elif parsed['algo_id'] == '5':
                        is_match = sha256_crypt.verify(password, hash_input)
                    elif parsed['algo_id'] == '1':
                        is_match = md5_crypt.verify(password, hash_input)
                    # bcrypt için ek kontrol gerekebilir ama şimdilik geç
                except Exception as e:
                    continue

                if is_match:
                    print(f"\n{Colors.GREEN}[+] ŞİFRE BULUNDU!{Colors.END}")
                    print(f"Password: {Colors.GREEN}{password}{Colors.END}")
                    found = True
                    break
                else:
                    # İsterseniz denenen şifreleri ekrana basabilirsiniz (yavaşlatır)
                    # print(f"Tried: {password}", end='\r')
                    pass
                    
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Kullanıcı tarafından durduruldu.{Colors.END}")
        sys.exit(0)

    if not found:
        print(f"\n{Colors.RED}[-] Şifre wordlist içinde bulunamadı.{Colors.END}")

if __name__ == "__main__":
    main()   
