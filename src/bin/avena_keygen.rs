use avena_overlay::{DeviceKeypair, NetworkConfig};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("generate") => {
            let output = args.get(2).map(PathBuf::from);
            let keypair = DeviceKeypair::generate();
            let device_id = keypair.device_id();
            let network = NetworkConfig::default();
            let overlay_ip = network.device_address(&device_id);

            if let Some(path) = output {
                let bytes = keypair.to_bytes();
                std::fs::write(&path, &*bytes).expect("failed to write keypair");
                eprintln!("Wrote keypair to {}", path.display());
            }

            println!("device_id={}", device_id);
            println!("overlay_ip={}", overlay_ip);
        }
        Some("from-seed") => {
            let seed_hex = args.get(2).expect("usage: avena-keygen from-seed <hex>");
            let seed_bytes = hex::decode(seed_hex).expect("invalid hex");
            if seed_bytes.len() != 32 {
                eprintln!("seed must be 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);

            let keypair = DeviceKeypair::from_seed(&seed);
            let device_id = keypair.device_id();
            let network = NetworkConfig::default();
            let overlay_ip = network.device_address(&device_id);

            println!("device_id={}", device_id);
            println!("overlay_ip={}", overlay_ip);
        }
        Some("from-file") => {
            let path = args.get(2).expect("usage: avena-keygen from-file <path>");
            let bytes = std::fs::read(path).expect("failed to read file");
            if bytes.len() != 32 {
                eprintln!("keypair file must be 32 bytes");
                std::process::exit(1);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);

            let keypair = DeviceKeypair::from_seed(&seed);
            let device_id = keypair.device_id();
            let network = NetworkConfig::default();
            let overlay_ip = network.device_address(&device_id);

            println!("device_id={}", device_id);
            println!("overlay_ip={}", overlay_ip);
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  avena-keygen generate [output-file]");
            eprintln!("  avena-keygen from-seed <64-char-hex>");
            eprintln!("  avena-keygen from-file <keypair-file>");
            std::process::exit(1);
        }
    }
}
