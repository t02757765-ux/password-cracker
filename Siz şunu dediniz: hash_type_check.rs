/*
 * =====================================================================================
 * PROJECT: Windows & Network Security Research - Advanced Hash Analyzer
 * AUTHOR: Tarık (Penetration Testing Expert & Researcher)
 * FILE: hash_type_check.rs
 * DESCRIPTION: A comprehensive hash identification engine with an internal 
 * vulnerability database. Covers Windows, Linux, and Web hashes.
 * =====================================================================================
 */

use std::env;
use std::collections::HashMap;

/// Represents a specific hash type with technical metadata.
#[derive(Clone)]
struct HashMetadata {
    name: &'static str,
    platform: &'static str,
    algorithm: &'static str,
    security_rating: &'static str,
    hashcat_mode: &'static str,
    john_format: &'static str,
    description: &'static str,
    is_salted: bool,
}

/// The core engine containing the hash knowledge base.
struct HashDatabase {
    records: HashMap<usize, Vec<HashMetadata>>,
}

impl HashDatabase {
    fn new() -> Self {
        let mut db = HashMap::new();

        // --- 32 CHARACTER HASHES (128-bit) ---
        db.insert(32, vec![
            HashMetadata {
                name: "NTLM",
                platform: "Windows",
                algorithm: "MD4(UTF-16LE(password))",
                security_rating: "CRITICAL VULNERABILITY",
                hashcat_mode: "1000",
                john_format: "nt",
                description: "Standard Windows storage. Vulnerable to Pass-the-Hash and Rainbow Tables.",
                is_salted: false,
            },
            HashMetadata {
                name: "MD5",
                platform: "General / Legacy",
                algorithm: "MD5",
                security_rating: "DEPRECATED",
                hashcat_mode: "0",
                john_format: "raw-md5",
                description: "Message-Digest algorithm 5. Used in legacy systems. Fast but highly insecure.",
                is_salted: false,
            },
            HashMetadata {
                name: "LM (LanMan)",
                platform: "Windows (Legacy)",
                algorithm: "DES based",
                security_rating: "EXTREMELY WEAK",
                hashcat_mode: "3000",
                john_format: "lm",
                description: "Splits password into two 7-char chunks. Extremely easy to crack.",
                is_salted: false,
            },
        ]);

        // --- 40 CHARACTER HASHES (160-bit) ---
        db.insert(40, vec![
            HashMetadata {
                name: "SHA-1",
                platform: "Generic",
                algorithm: "SHA-1",
                security_rating: "LOW",
                hashcat_mode: "100",
                john_format: "raw-sha1",
                description: "Used in older SSL/TLS and Git. Collision attacks are proven.",
                is_salted: false,
            },
            HashMetadata {
                name: "MySQL 4.1+",
                platform: "Database",
                algorithm: "SHA1(SHA1(password))",
                security_rating: "MEDIUM",
                hashcat_mode: "300",
                john_format: "mysql-sha1",
                description: "Used in modern MySQL/MariaDB for user authentication.",
                is_salted: false,
            },
        ]);

        // --- 64 CHARACTER HASHES (256-bit) ---
        db.insert(64, vec![
            HashMetadata {
                name: "SHA-256",
                platform: "Modern Web / Blockchain",
                algorithm: "SHA-2",
                security_rating: "HIGH",
                hashcat_mode: "1400",
                john_format: "raw-sha256",
                description: "Current industry standard for non-password hashing applications.",
                is_salted: false,
            },
            HashMetadata {
                name: "Django (PBKDF2-SHA256)",
                platform: "Web Framework",
                algorithm: "PBKDF2 with SHA256",
                security_rating: "VERY HIGH",
                hashcat_mode: "10000",
                john_format: "pbkdf2-hmac-sha256",
                description: "Uses multiple iterations and salts. Very resistant to brute force.",
                is_salted: true,
            },
        ]);

        // --- 128 CHARACTER HASHES (512-bit) ---
        db.insert(128, vec![
            HashMetadata {
                name: "SHA-512",
                platform: "General",
                algorithm: "SHA-2 (512-bit)",
                security_rating: "HIGH",
                hashcat_mode: "1700",
                john_format: "raw-sha512",
                description: "Extremely wide output, used in high-security applications.",
                is_salted: false,
            },
            HashMetadata {
                name: "Sha512crypt ($6$)",
                platform: "Linux (Debian/Ubuntu/CentOS)",
                algorithm: "SHA-512 with Salt",
                security_rating: "VERY HIGH",
                hashcat_mode: "1800",
                john_format: "sha512crypt",
                description: "Standard Linux shadow storage. Uses salt and thousands of rounds.",
                is_salted: true,
            },
        ]);

        HashDatabase { records: db }
    }

    fn analyze(&self, hash: &str) {
        let h_len = hash.len();
        println!("\n[+] Analysis Results for length: {} characters", h_len);
        println!("------------------------------------------------------------");

        match self.records.get(&h_len) {
            Some(matches) => {
                for m in matches {
                    println!("[TYPE]        : {}", m.name);
                    println!("[PLATFORM]    : {}", m.platform);
                    println!("[ALGORITHM]   : {}", m.algorithm);
                    println!("[SECURITY]    : {}", m.security_rating);
                    println!("[HASHCAT MODE]: {}", m.hashcat_mode);
                    println!("[JOHN FORMAT] : {}", m.john_format);
                    println!("[SALTED]      : {}", if m.is_salted { "Yes" } else { "No" });
                    println!("[INFO]        : {}", m.description);
                    println!("------------------------------------------------------------");
                }
            }
            None => {
                println!("[!] Error: No direct length match found in the local database.");
                println!("[*] Research Note: Check for common prefixes like $2y$ (bcrypt) or $1$ (md5crypt).");
            }
        }
    }
}

fn print_banner() {
    let banner = r#"
    __  __           _      _____                                    
   |  \/  |         | |    |  __ \                                   
   | \  / | __ _ ___| |__  | |  | | ___  ___ ___  _ __   ___ _ __ 
   | |\/| |/ _` / __| '_ \ | |  | |/ _ \/ __/ _ \| '_ \ / _ \ '__|
   | |  | | (_| \__ \ | | || |__| |  __/ (_| (_) | | | |  __/ |   
   |_|  |_|\__,_|___/_| |_||_____/ \___|\___\___/|_| |_|\___|_|   
                                                                   
    Version: 2.0.1 | Research Domain: Windows & Network Security
    Developed by: Tarık (Sızma Testi Uzmanı)
    "#;
    println!("{}", banner);
}

fn print_detailed_research_notes() {
    println!("\n[!] RESEARCH DATABASE - ATTACK VECTORS [!]");
    println!("1. Dictionary Attack: Uses a pre-defined list of passwords (wordlists).");
    println!("2. Brute Force: Mathematically tries every combination. Speed depends on GPU/CPU.");
    println!("3. Rule-Based Attack: Applies logic to wordlists (e.g., adding '123' or capitalization).");
    println!("4. Rainbow Tables: Pre-computed tables of hashes. Ineffective against Salted hashes.");
    println!("5. Pass-the-Hash: Using the hash directly without cracking to authenticate on Windows.");
    println!("------------------------------------------------------------");
}

fn main() {
    print_banner();
    
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[!] Usage: ./hash_type_check <hash_to_analyze>");
        println!("[*] Example: ./hash_type_check 31d6cfe0d16ae931b73c59d7e0c089c0");
        return;
    }

    let target = &args[1];
    let db = HashDatabase::new();

    db.analyze(target);
    print_detailed_research_notes();

    println!("\n[LOG] Scan complete. Proceed with ethical testing.");
}
