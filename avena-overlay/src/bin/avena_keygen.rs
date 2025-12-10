use avena_overlay::{
    create_self_signed_jwt, decode_jwt_unsafe, issue_jwt, DeviceKeypair, NetworkConfig,
};
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
            eprintln!("  avena-keygen cert init-ca <keypair-file> <output-jwt>");
            eprintln!("  avena-keygen cert issue <issuer-key> <issuer-jwt> <subject-key> <output-cert> [--days=N]");
            eprintln!("  avena-keygen cert show <jwt-file>");
            std::process::exit(1);
        }
    }
}

fn cmd_cert_init_ca(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: avena-keygen cert init-ca <keypair-file> <output-jwt>");
        std::process::exit(1);
    }

    let keypair = load_keypair(&args[0]);
    let output = PathBuf::from(&args[1]);

    let jwt = create_self_signed_jwt(&keypair, 3650);
    std::fs::write(&output, &jwt).expect("failed to write JWT");

    eprintln!("Created root certificate (JWT): {}", output.display());
    println!("device_id={}", keypair.device_id());
}

fn cmd_cert_issue(args: &[String]) {
    if args.len() < 4 {
        eprintln!("usage: avena-keygen cert issue <issuer-key> <issuer-jwt> <subject-key> <output-cert> [--days=N]");
        std::process::exit(1);
    }

    let issuer_keypair = load_keypair(&args[0]);
    let _issuer_jwt = load_jwt(&args[1]);
    let subject_keypair = load_keypair(&args[2]);
    let output = PathBuf::from(&args[3]);

    let days = args
        .get(4)
        .and_then(|s| s.strip_prefix("--days="))
        .and_then(|d| d.parse().ok())
        .unwrap_or(365);

    let subject_jwt = issue_jwt(
        &issuer_keypair,
        subject_keypair.device_id(),
        subject_keypair.public_key(),
        days,
    );

    std::fs::write(&output, &subject_jwt).expect("failed to write cert");

    eprintln!("Issued certificate: {}", output.display());
    println!("device_id={}", subject_keypair.device_id());
}

fn cmd_cert_show(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: avena-keygen cert show <jwt-file>");
        std::process::exit(1);
    }

    let path = &args[0];
    let content = std::fs::read_to_string(path).expect("failed to read file");
    let trimmed = content.trim();

    println!("Certificate (JWT):");
    print_jwt(trimmed, "  ");
}

fn print_jwt(jwt: &str, indent: &str) {
    match decode_jwt_unsafe(jwt) {
        Ok(claims) => {
            println!("{}sub (device_id): {}", indent, claims.sub);
            println!("{}iss (issuer_id): {}", indent, claims.iss);
            println!("{}iat: {}", indent, claims.not_before());
            println!("{}exp: {}", indent, claims.not_after());
            println!("{}self_signed: {}", indent, claims.is_self_signed());
        }
        Err(e) => {
            println!("{}error decoding: {}", indent, e);
        }
    }
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

fn load_jwt(path: &str) -> String {
    std::fs::read_to_string(path)
        .expect("failed to read JWT file")
        .trim()
        .to_string()
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  avena-keygen generate [output-file]");
    eprintln!("  avena-keygen from-seed <64-char-hex>");
    eprintln!("  avena-keygen from-file <keypair-file>");
    eprintln!("  avena-keygen cert init-ca <keypair-file> <output-jwt>");
    eprintln!("  avena-keygen cert issue <issuer-key> <issuer-jwt> <subject-key> <output-cert> [--days=N]");
    eprintln!("  avena-keygen cert show <jwt-file>");
    std::process::exit(1);
}
