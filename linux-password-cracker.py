import hashlib
import sys
import os

# Renk kodları (Windows terminalinde düzgün çalışması için basit tutuldu)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

def detect_hash_type(hash_str):
    """Hash tipini otomatik algılar."""
    hash_str = hash_str.strip()
    
    # Linux Shadow Formatları
    if hash_str.startswith("$1$"):
        return "MD5-Crypt"
    elif hash_str.startswith("$5$"):
        return "SHA-256-Crypt"
    elif hash_str.startswith("$6$"):
        return "SHA-512-Crypt"
    elif hash_str.startswith("$2a$") or hash_str.startswith("$2b$") or hash_str.startswith("$2y$"):
        return "Blowfish (bcrypt)"
    
    # Ham Hash Uzunluk Kontrolü
    if len(hash_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "SHA-256 (Raw)"
    elif len(hash_str) == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "SHA-512 (Raw)"
    elif len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "MD5 (Raw)"
        
    return "Bilinmeyen"

def crack_raw_hash(target_hash, wordlist_path, algo="sha512"):
    """Ham (Raw) hash'leri kırar (Sizin verdiğiniz format için)."""
    print(f"{Colors.YELLOW}[!] Tespit Edilen: {algo}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Hedef Hash: {target_hash[:20]}...{Colors.RESET}")
    
    if not os.path.exists(wordlist_path):
        print(f"{Colors.RED}[-] Wordlist dosyası bulunamadı: {wordlist_path}{Colors.RESET}")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                # Hash hesaplama
                if algo == "sha512":
                    computed_hash = hashlib.sha512(password.encode('utf-8')).hexdigest()
                elif algo == "sha256":
                    computed_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                elif algo == "md5":
                    computed_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
                else:
                    continue

                if computed_hash.lower() == target_hash.lower():
                    print(f"\n{Colors.GREEN}[+] ŞİFRE BULUNDU!{Colors.RESET}")
                    print(f"{Colors.GREEN}Şifre: {password}{Colors.RESET}")
                    print(f"{Colors.GREEN}Hash : {computed_hash}{Colors.RESET}")
                    return
                else:
                    # İlerleme göstergesi (isteğe bağlı, çok hızlı akar)
                    sys.stdout.write('.')
                    sys.stdout.flush()

        print(f"\n{Colors.RED}[-] Şifre wordlist içinde bulunamadı.{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}[-] Hata oluştu: {str(e)}{Colors.RESET}")

def main():
    print("========================================")
    print("   Multi-Platform Password Cracker v2   ")
    print("   (Linux Shadow & Raw Hash Desteği)    ")
    print("========================================\n")

    # Kullanıcıdan hash al
    target_hash = input("Kırılacak hash'i yapıştırın: ").strip()
    
    if not target_hash:
        print(f"{Colors.RED}[-] Hash girilmedi.{Colors.RESET}")
        return

    hash_type = detect_hash_type(target_hash)
    print(f"{Colors.YELLOW}[i] Algılanan Hash Tipi: {hash_type}{Colors.RESET}\n")

    # Wordlist yolu
    default_wordlist = "rockyou.txt"
    wordlist_path = input(f"Wordlist dosya yolu (Enter ile '{default_wordlist}'): ").strip()
    if not wordlist_path:
        wordlist_path = default_wordlist

    # İşlem türüne göre yönlendirme
    if "Raw" in hash_type:
        if "SHA-512" in hash_type:
            crack_raw_hash(target_hash, wordlist_path, "sha512")
        elif "SHA-256" in hash_type:
            crack_raw_hash(target_hash, wordlist_path, "sha256")
        elif "MD5" in hash_type:
            crack_raw_hash(target_hash, wordlist_path, "md5")
    elif hash_type in ["MD5-Crypt", "SHA-256-Crypt", "SHA-512-Crypt"]:
        print(f"{Colors.RED}[-] Uyarı: Shadow formatı ($x$) şu an bu basit scriptte desteklenmiyor.{Colors.RESET}")
        print(f"{Colors.YELLOW}[i] Bu format için 'passlib' kütüphanesi ile özel bir fonksiyon gerekir.{Colors.RESET}")
        # İsterseniz buraya passlib entegrasyonu da eklenebilir ama şimdilik raw odaklı gidelim.
        # Passlib gerektirmemesi için shadow formatını da manuel parse edip hashlib ile çözebiliriz.
        # Aşağıda basit bir shadow parser ekliyorum:
        crack_shadow_hash(target_hash, wordlist_path)
    else:
        print(f"{Colors.RED}[-] Desteklenmeyen hash formatı.{Colors.RESET}")

def crack_shadow_hash(full_hash, wordlist_path):
    """Linux Shadow ($6$salt$hash) formatını manuel olarak çözer."""
    parts = full_hash.split('$')
    if len(parts) < 4:
        print(f"{Colors.RED}[-] Geçersiz Shadow formatı.{Colors.RESET}")
        return

    algo_id = parts[1]
    salt = parts[2]
    stored_hash = parts[3]
    
    print(f"{Colors.YELLOW}[+] Shadow Formatı Analiz Edildi:{Colors.RESET}")
    print(f"    Algoritma ID: {algo_id}")
    print(f"    Salt: {salt}")
    
    import crypt # Not: Windows'ta bu satır hata verir, bu yüzden Windows kullanıcıları için passlib şarttır.
                 # Ancak kullanıcı Windows'ta ise ve crypt yoksa, bu fonksiyon çalışmaz.
                 # BU NEDENLE WINDOWS İÇİN PASSLIB ŞARTTIR VEYA SADECE RAW HASH KULLANILMALIDIR.
    
    # Windows uyumluluğu için passlib kontrolü
    try:
        from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
        use_passlib = True
    except ImportError:
        use_passlib = False
        if os.name == 'nt':
            print(f"{Colors.RED}[-] Windows'ta Shadow hash kırmak için 'pip install passlib' gereklidir.{Colors.RESET}")
            print(f"{Colors.YELLOW}[i] Sadece Raw (ham) hash deneyebilirsiniz.{Colors.RESET}")
            return

    if not os.path.exists(wordlist_path):
        # Basit test kelimesi oluştur (dosya yoksa)
        print(f"{Colors.YELLOW}[!] Wordlist bulunamadı, basit test yapılıyor...{Colors.RESET}")
        test_words = ["123456", "password", "test123", "linux", "root"]
    else:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Dosyayı satır satır okumak yerine bellek için iteratör kullanıyoruz
            for line in f:
                password = line.strip()
                if not password: continue
                
                if algo_id == "6":
                    if use_passlib:
                        if sha512_crypt.verify(password, full_hash):
                            print_found(password)
                            return
                    else:
                        # Fallback (Windows'ta passlib yoksa çalışmaz)
                        pass 
                elif algo_id == "5":
                     if use_passlib:
                        if sha256_crypt.verify(password, full_hash):
                            print_found(password)
                            return
                elif algo_id == "1":
                     if use_passlib:
                        if md5_crypt.verify(password, full_hash):
                            print_found(password)
                            return
                            
        print(f"{Colors.RED}[-] Şifre bulunamadı.{Colors.RESET}")

def print_found(pwd):
    print(f"\n{Colors.GREEN}[+] ŞİFRE BULUNDU!{Colors.RESET}")
    print(f"{Colors.GREEN}Şifre: {pwd}{Colors.RESET}")

if __name__ == "__main__":
    # Eğer passlib yüklü değilse ve Windows ise uyarı verelim ama çalışmaya devam edelim (Raw için)
    if os.name == 'nt':
        try:
            import passlib
        except ImportError:
            print(f"{Colors.YELLOW}[Uyarı] 'passlib' yüklü değil. Sadece Raw (Ham) SHA/MD5 hash'leri kırabilirsiniz.{Colors.RESET}")
            print(f"{Colors.YELLOW}[Bilgi] Linux Shadow ($6$...) hash'leri için: pip install passlib{Colors.RESET}\n")
            
    main()
