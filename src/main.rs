
use sha2::{Digest, Sha256};
use std::{env, fs};

/* Example - sha256 computed for a binary
deepak_ubuntu@LAPTOP-Q19HIR5K:~/rust/crypto$ sha256sum firmware.bin 
077fe6272119a04788489ce35621d2c181a2d605c995fe8ab731919294c5d781  firmware.bin
deepak_ubuntu@LAPTOP-Q19HIR5K:~/rust/crypto$ cargo run -- firmware.bin 077fe6272119a04788489ce35621d2c181a2d605c995fe8ab731919294c5d781 
*/

fn hex_to_32bytes(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();

    if hex.len() != 64 {
        return Err(format!(
            "Expected 64 hex chars (32 bytes), got {} chars",
            hex.len()
        ));
    }

    let mut out = [0u8; 32];
    for i in 0..32 {
        let idx = i * 2;
        let byte_str = &hex[idx..idx + 2];
        out[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex at position {}: {}", idx, e))?;
    }
    Ok(out)
}

fn sha256_file(path: &str) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <firmware.bin> <expected_sha256_hex>", args[0]);
        eprintln!("Example: {} firmware.bin d2c7... (64 hex chars)", args[0]);
        std::process::exit(2);
    }

    let fw_path = &args[1];
    let expected_hex = &args[2];


    println!("fw_path: {}", fw_path);

    println!("finished main function.");

    let expected = match hex_to_32bytes(expected_hex) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Bad expected hash: {}", msg);
            std::process::exit(2);
        }
    };

    let actual = match sha256_file(fw_path) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(2);
        }
    };

    println!("Computed SHA-256: {}", to_hex(&actual));
    println!("Expected SHA-256: {}", to_hex(&expected));

    if actual == expected {
        println!("INTEGRITY CHECK: PASS");
        std::process::exit(0);
    } else {
        println!("INTEGRITY CHECK: FAIL (hash mismatch)");
        std::process::exit(1);
    }

}
