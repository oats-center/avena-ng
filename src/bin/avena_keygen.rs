use avena_overlay::{Certificate, CertificateChain, DeviceKeypair, NetworkConfig};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("generate") => cmd_generate(&args[2..]),
        Some("from-seed") => cmd_from_seed(&args[2..]),
        Some("from-file") => cmd_from_file(&args[2..]),
        Some("cert") => cmd_cert(&args[2..]),
        _ => print_usage(),
    }
}

fn cmd_generate(args: &[String]) {
    let output = args.first().map(PathBuf::from);
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

fn cmd_from_seed(args: &[String]) {
    let seed_hex = args.first().expect("usage: avena-keygen from-seed <hex>");
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

fn cmd_from_file(args: &[String]) {
    let path = args.first().expect("usage: avena-keygen from-file <path>");
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

fn cmd_cert(args: &[String]) {
    match args.first().map(|s| s.as_str()) {
        Some("init-ca") => cmd_cert_init_ca(&args[1..]),
        Some("issue") => cmd_cert_issue(&args[1..]),
        Some("show") => cmd_cert_show(&args[1..]),
        _ => {
            eprintln!("Usage:");
            eprintln!("  avena-keygen cert init-ca <keypair-file> <output-cert>");
            eprintln!("  avena-keygen cert issue <issuer-key> <issuer-cert> <subject-key> <output-chain> [--days=N]");
            eprintln!("  avena-keygen cert show <cert-or-chain-file>");
            std::process::exit(1);
        }
    }
}

fn cmd_cert_init_ca(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: avena-keygen cert init-ca <keypair-file> <output-cert>");
        std::process::exit(1);
    }

    let keypair = load_keypair(&args[0]);
    let output = PathBuf::from(&args[1]);

    let cert = Certificate::new_self_signed(&keypair, 3650);
    let json = serde_json::to_string_pretty(&cert).expect("failed to serialize cert");
    std::fs::write(&output, &json).expect("failed to write cert");

    eprintln!("Created root certificate: {}", output.display());
    println!("device_id={}", keypair.device_id());
}

fn cmd_cert_issue(args: &[String]) {
    if args.len() < 4 {
        eprintln!("usage: avena-keygen cert issue <issuer-key> <issuer-cert> <subject-key> <output-chain> [--days=N]");
        std::process::exit(1);
    }

    let issuer_keypair = load_keypair(&args[0]);
    let issuer_cert: Certificate = load_json(&args[1]);
    let subject_keypair = load_keypair(&args[2]);
    let output = PathBuf::from(&args[3]);

    let days = args
        .get(4)
        .and_then(|s| s.strip_prefix("--days="))
        .and_then(|d| d.parse().ok())
        .unwrap_or(365);

    let subject_cert = Certificate::issue(
        &issuer_keypair,
        subject_keypair.device_id(),
        subject_keypair.public_key(),
        days,
    );

    let chain = if issuer_cert.is_self_signed() {
        CertificateChain::with_intermediates(subject_cert, vec![issuer_cert])
    } else {
        CertificateChain::new(subject_cert)
    };

    let json = serde_json::to_string_pretty(&chain).expect("failed to serialize chain");
    std::fs::write(&output, &json).expect("failed to write chain");

    eprintln!("Issued certificate chain: {}", output.display());
    println!("device_id={}", subject_keypair.device_id());
}

fn cmd_cert_show(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: avena-keygen cert show <cert-or-chain-file>");
        std::process::exit(1);
    }

    let path = &args[0];
    let bytes = std::fs::read(path).expect("failed to read file");

    if let Ok(chain) = serde_json::from_slice::<CertificateChain>(&bytes) {
        println!("Certificate Chain:");
        println!("  Leaf:");
        print_cert(&chain.leaf, "    ");
        for (i, intermediate) in chain.intermediates.iter().enumerate() {
            println!("  Intermediate {}:", i);
            print_cert(intermediate, "    ");
        }
    } else if let Ok(cert) = serde_json::from_slice::<Certificate>(&bytes) {
        println!("Certificate:");
        print_cert(&cert, "  ");
    } else {
        eprintln!("Failed to parse as certificate or chain");
        std::process::exit(1);
    }
}

fn print_cert(cert: &Certificate, indent: &str) {
    println!("{}device_id: {}", indent, cert.device_id);
    println!("{}issuer_id: {}", indent, cert.issuer_id);
    println!("{}not_before: {}", indent, cert.not_before);
    println!("{}not_after: {}", indent, cert.not_after);
    println!("{}self_signed: {}", indent, cert.is_self_signed());
}

fn load_keypair(path: &str) -> DeviceKeypair {
    let bytes = std::fs::read(path).expect("failed to read keypair file");
    if bytes.len() != 32 {
        eprintln!("keypair file must be 32 bytes");
        std::process::exit(1);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    DeviceKeypair::from_seed(&seed)
}

fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let bytes = std::fs::read(path).expect("failed to read file");
    serde_json::from_slice(&bytes).expect("failed to parse JSON")
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  avena-keygen generate [output-file]");
    eprintln!("  avena-keygen from-seed <64-char-hex>");
    eprintln!("  avena-keygen from-file <keypair-file>");
    eprintln!("  avena-keygen cert init-ca <keypair-file> <output-cert>");
    eprintln!("  avena-keygen cert issue <issuer-key> <issuer-cert> <subject-key> <output-chain> [--days=N]");
    eprintln!("  avena-keygen cert show <cert-or-chain-file>");
    std::process::exit(1);
}
