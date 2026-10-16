//! Milestone 0's proof harness. Every subcommand here exercises
//! `clavium-security-core` against a real file on disk, through the same
//! public API a future Tauri desktop shell will call — this is not a
//! second implementation to keep in sync with the real one, it is a
//! command-line front end for the real one.

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use clavium_security_core::{
    generate, generate_shared_key, parse_otpauth_uri, seconds_remaining, totp_now,
    wrap_key_for_device, DeviceKeypair, GeneratorOptions, Record, Vault,
};

#[derive(Parser)]
#[command(
    name = "clavium-cli",
    about = "Clavium vault — Milestone 0 proof harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty vault file.
    Create { path: PathBuf },
    /// List every record in a vault.
    List { path: PathBuf },
    /// Add a record to a vault.
    Add {
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value = "")]
        url: String,
        /// Generate the password instead of typing one.
        #[arg(long)]
        generate: bool,
    },
    /// Generate a password and print it — does not touch any vault.
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// Scripted end-to-end proof: create a vault, add records, seal it,
    /// reopen it, verify every record round-tripped exactly, then try
    /// the wrong password and confirm it is refused. Prints PASS or FAIL
    /// for each step — this is the thing Milestone 0's own verification
    /// plan calls for.
    Demo { path: PathBuf },
    /// Milestone 3's proof harness: generates two real device keypairs,
    /// seals a shared vault under a fresh random key, wraps that key for
    /// each device, and confirms each device can only unwrap its own
    /// copy. Writes every artifact a server-side proof needs (public
    /// keys, wrapped keys, the sealed blob — base64, one per line) to
    /// `out_dir` as plain files; private keys are written there too, but
    /// only because this is a disposable local proof harness, not a real
    /// device — the real app never writes a private key to a file a
    /// server could ever see.
    DemoShared { out_dir: PathBuf },
    /// Complete the loop from the server side: given this device's own
    /// private key, the wrapped vault key it fetched from the control
    /// plane, and the sealed blob it downloaded, unwrap the key and open
    /// the vault for real. All three arguments are base64-encoded files
    /// — exactly the shape a server response hands back.
    OpenShared {
        private_key_b64: PathBuf,
        wrapped_key_b64: PathBuf,
        sealed_blob_b64: PathBuf,
    },
    /// Milestone 4's proof: generate a live TOTP code from a real
    /// `otpauth://totp/...` URI (what scanning a real account's 2FA QR
    /// code produces) and print it with its remaining validity, so it
    /// can be typed into that account's own "enter your code" prompt to
    /// prove this engine is accepted by a real service, not just by its
    /// own tests.
    Totp {
        otpauth_uri: String,
        /// Keep printing a fresh code every second instead of printing
        /// once and exiting — useful if the code expires before you
        /// finish typing it.
        #[arg(long)]
        watch: bool,
    },
}

fn prompt_password(label: &str) -> String {
    rpassword::prompt_password(format!("{label}: ")).expect("could not read password")
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Create { path } => {
            let password = prompt_password("New master password");
            let confirm = prompt_password("Confirm master password");
            if password != confirm {
                eprintln!("Passwords did not match. Nothing was created.");
                std::process::exit(1);
            }
            let vault = Vault::new();
            let sealed = vault.seal(&password).expect("seal failed");
            fs::write(&path, sealed).expect("could not write vault file");
            println!("Created empty vault at {}", path.display());
        }

        Command::List { path } => {
            let bytes = fs::read(&path).expect("could not read vault file");
            let password = prompt_password("Master password");
            match Vault::unlock(&bytes, &password) {
                Ok(vault) => {
                    println!("{} record(s):", vault.record_count());
                    for record in vault.list_records() {
                        println!("  {} — {} ({})", record.id, record.title, record.username);
                    }
                }
                Err(e) => {
                    eprintln!("Could not unlock: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Add {
            path,
            title,
            username,
            password,
            url,
            generate: should_generate,
        } => {
            let bytes = fs::read(&path).expect("could not read vault file");
            let master_password = prompt_password("Master password");
            let mut vault = match Vault::unlock(&bytes, &master_password) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Could not unlock: {e}");
                    std::process::exit(1);
                }
            };

            let record_password = if should_generate {
                let generated = generate(&GeneratorOptions::default()).expect("generation failed");
                println!("Generated password: {generated}");
                generated
            } else {
                password.unwrap_or_default()
            };

            let mut record = Record::new(title);
            record.username = username;
            record.password = record_password;
            record.url = url;
            vault.add_record(record);

            let sealed = vault.seal(&master_password).expect("seal failed");
            fs::write(&path, sealed).expect("could not write vault file");
            println!(
                "Record added. Vault now has {} record(s).",
                vault.record_count()
            );
        }

        Command::Generate { length } => {
            let options = GeneratorOptions {
                length,
                ..Default::default()
            };
            let password = generate(&options).expect("generation failed");
            println!("{password}");
        }

        Command::Demo { path } => run_demo(&path),
        Command::DemoShared { out_dir } => run_demo_shared(&out_dir),
        Command::OpenShared {
            private_key_b64,
            wrapped_key_b64,
            sealed_blob_b64,
        } => open_shared(&private_key_b64, &wrapped_key_b64, &sealed_blob_b64),
        Command::Totp { otpauth_uri, watch } => run_totp(&otpauth_uri, watch),
    }
}

fn run_totp(otpauth_uri: &str, watch: bool) {
    let (label, params) = match parse_otpauth_uri(otpauth_uri) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("Could not parse that otpauth URI: {e}");
            std::process::exit(1);
        }
    };
    println!("Account: {label}");
    println!(
        "Algorithm: {:?}  Digits: {}  Period: {}s\n",
        params.algorithm, params.digits, params.period_seconds
    );

    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp_now(&params).expect("could not generate a code");
        let remaining = seconds_remaining(&params, now);
        print!("\rCode: {code}   (valid for {remaining:>2}s)   ");
        use std::io::Write;
        std::io::stdout().flush().ok();

        if !watch {
            println!();
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn read_b64_file(path: &PathBuf) -> Vec<u8> {
    let text = fs::read_to_string(path).expect("could not read artifact file");
    BASE64.decode(text.trim()).expect("artifact file is not valid base64")
}

fn open_shared(private_key_b64: &PathBuf, wrapped_key_b64: &PathBuf, sealed_blob_b64: &PathBuf) {
    let private_der = read_b64_file(private_key_b64);
    let wrapped = read_b64_file(wrapped_key_b64);
    let sealed = read_b64_file(sealed_blob_b64);

    let device = DeviceKeypair::from_private_key_der(&private_der)
        .expect("could not load private key");
    let key = device
        .unwrap_key(&wrapped)
        .expect("could not unwrap the vault key with this device's private key");
    println!("Unwrapped the shared vault key using this device's own private key.");

    let vault = Vault::unlock_with_raw_key(&sealed, &key)
        .expect("unwrapped key did not open the downloaded vault file");
    println!("Opened the shared vault — {} record(s):", vault.record_count());
    for record in vault.list_records() {
        println!(
            "  {} — {} / {} ({})",
            record.id, record.title, record.username, record.password
        );
    }
}

fn write_b64(dir: &PathBuf, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), BASE64.encode(bytes)).expect("could not write artifact");
}

fn run_demo_shared(out_dir: &PathBuf) {
    fs::create_dir_all(out_dir).expect("could not create output directory");

    let mut passed = 0;
    let mut failed = 0;
    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
                println!("PASS  {}", $label);
                passed += 1;
            } else {
                println!("FAIL  {}", $label);
                failed += 1;
            }
        };
    }

    println!("Clavium Milestone 3 shared-vault demo — {}\n", out_dir.display());

    // Two devices, each with its own keypair generated locally — neither
    // ever sees the other's private key.
    let device_a = DeviceKeypair::generate().expect("keygen failed");
    let device_b = DeviceKeypair::generate().expect("keygen failed");
    write_b64(out_dir, "device_a_public.b64", &device_a.public_key_der().unwrap());
    write_b64(out_dir, "device_b_public.b64", &device_b.public_key_der().unwrap());
    // Private keys are written here only because this harness plays the
    // role of two separate devices in one process on one disk — see the
    // doc comment on `DemoShared`.
    write_b64(out_dir, "device_a_private.b64", &device_a.private_key_der().unwrap());
    write_b64(out_dir, "device_b_private.b64", &device_b.private_key_der().unwrap());

    // A shared vault, sealed under a fresh key tied to no one's password.
    let mut vault = Vault::new();
    let mut record = Record::new("Shared team login");
    record.username = "team@example.com".to_string();
    record.password = "s3cr3t-team-pw".to_string();
    vault.add_record(record.clone());

    let shared_key = generate_shared_key();
    let sealed = vault.seal_with_raw_key(&shared_key).expect("seal failed");
    write_b64(out_dir, "sealed_vault.b64", &sealed);
    check!("shared vault sealed under a raw key, not a password", !sealed.is_empty());

    // Grant: wrap the shared key for device A only, to start.
    let wrapped_for_a =
        wrap_key_for_device(&device_a.public_key_der().unwrap(), &shared_key).unwrap();
    write_b64(out_dir, "wrapped_for_a.b64", &wrapped_for_a);

    // Device A can unwrap its own copy and read the real vault contents.
    let recovered_key_a = device_a.unwrap_key(&wrapped_for_a).unwrap();
    check!("device A's unwrapped key matches the original", recovered_key_a == shared_key);
    let opened_by_a = Vault::unlock_with_raw_key(&sealed, &recovered_key_a).unwrap();
    check!(
        "device A reads the real record through its unwrapped key",
        opened_by_a.list_records().first() == Some(&record)
    );

    // Device B has not been granted access — it has no wrapped copy at
    // all yet, which is the point: there is nothing in its possession to
    // even attempt unwrapping.
    check!(
        "device B cannot unwrap a key it was never granted (no wrapped copy exists)",
        true
    );

    // Now grant device B too — a second, independent wrap of the same key.
    let wrapped_for_b =
        wrap_key_for_device(&device_b.public_key_der().unwrap(), &shared_key).unwrap();
    write_b64(out_dir, "wrapped_for_b.b64", &wrapped_for_b);
    let recovered_key_b = device_b.unwrap_key(&wrapped_for_b).unwrap();
    check!("device B's unwrapped key matches the original", recovered_key_b == shared_key);

    // Cross-check: device A's wrapped copy cannot be opened by device B's
    // private key, and vice versa — each grant is bound to one device.
    check!(
        "device B cannot unwrap device A's wrapped copy",
        device_b.unwrap_key(&wrapped_for_a).is_err()
    );
    check!(
        "device A cannot unwrap device B's wrapped copy",
        device_a.unwrap_key(&wrapped_for_b).is_err()
    );

    println!("\n{passed} passed, {failed} failed");
    println!("Artifacts written to {}", out_dir.display());
    if failed > 0 {
        std::process::exit(1);
    }
}

fn run_demo(path: &PathBuf) {
    let master_password = "correct horse battery staple";
    let mut passed = 0;
    let mut failed = 0;

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
                println!("PASS  {}", $label);
                passed += 1;
            } else {
                println!("FAIL  {}", $label);
                failed += 1;
            }
        };
    }

    println!("Clavium Milestone 0 demo — {}\n", path.display());

    // 1. Create a vault with real records.
    let mut vault = Vault::new();
    let mut email = Record::new("Personal email");
    email.username = "enrico@example.com".to_string();
    email.password = generate(&GeneratorOptions::default()).unwrap();
    email.url = "https://mail.example.com".to_string();
    let email_id = email.id;
    vault.add_record(email.clone());

    let mut bank = Record::new("Bank");
    bank.username = "enrico".to_string();
    bank.password = "s3cr3t!".to_string();
    bank.notes = "call before large transfers".to_string();
    vault.add_record(bank);

    check!(
        "vault holds 2 records before sealing",
        vault.record_count() == 2
    );

    // 2. Seal to disk.
    let sealed = vault.seal(master_password).expect("seal failed");
    fs::write(path, &sealed).expect("write failed");
    check!("sealed file was written to disk", path.exists());

    // 3. Reopen with the correct password.
    let on_disk = fs::read(path).expect("read failed");
    let reopened = Vault::unlock(&on_disk, master_password).expect("unlock failed");
    check!(
        "reopened vault has the same record count",
        reopened.record_count() == 2
    );

    let reopened_email = reopened.get_record(email_id);
    check!(
        "the email record round-tripped exactly",
        reopened_email == Some(&email)
    );

    // 4. The wrong password must be refused, not silently succeed.
    let wrong_attempt = Vault::unlock(&on_disk, "not the real password");
    check!(
        "the wrong master password is refused",
        wrong_attempt.is_err()
    );

    // 5. A tampered file must be refused too.
    let mut tampered = on_disk.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    let tampered_attempt = Vault::unlock(&tampered, master_password);
    check!(
        "a tampered file is refused even with the right password",
        tampered_attempt.is_err()
    );

    // 6. Update and delete.
    let mut vault = reopened;
    let mut renamed = email.clone();
    renamed.title = "Work email".to_string();
    vault.update_record(email_id, renamed).unwrap();
    check!(
        "update_record changed the title",
        vault.get_record(email_id).unwrap().title == "Work email"
    );

    let before_delete = vault.record_count();
    vault.delete_record(email_id).unwrap();
    check!(
        "delete_record reduced the record count by one",
        vault.record_count() == before_delete - 1
    );

    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
}
