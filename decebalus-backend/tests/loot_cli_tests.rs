//! End-to-end check of `decebalus-backend loot decrypt <path>`: encrypts loot the
//! same way `nxc_common::save_loot` does, then shells out to the real binary to
//! confirm the CLI's path-based engagement lookup and decryption round-trip.
//!
//! Both scenarios live in one #[test] fn: `crypto::current()` is a process-global
//! singleton, so a second test in this binary racing to initialize it first would
//! make either scenario flaky.

use std::process::Command;

#[test]
fn loot_decrypt_cli_round_trips_and_rejects_wrong_key() {
    let data_dir = std::env::temp_dir().join(format!("decebalus_loot_cli_data_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    decebalus_backend::services::crypto::init(&data_dir).unwrap();
    let key_hex = std::fs::read_to_string(data_dir.join("master.key")).unwrap();
    let key_hex = key_hex.trim();

    let loot_root = std::env::temp_dir().join(format!("decebalus_loot_cli_{}", std::process::id()));
    let eng_dir = loot_root.join("eng-42");
    std::fs::create_dir_all(&eng_dir).unwrap();
    let loot_path = eng_dir.join("kerberoast.txt");

    let plaintext = b"$krb5tgs$23$*svc_web$ACME.LOCAL$http/web*$abc...def";
    let ciphertext = decebalus_backend::services::crypto::encrypt("eng-42", plaintext);
    std::fs::write(&loot_path, &ciphertext).unwrap();

    // Right key, path names the right engagement: decrypts cleanly.
    let ok = Command::new(env!("CARGO_BIN_EXE_decebalus-backend"))
        .args(["loot", "decrypt", loot_path.to_str().unwrap()])
        .env("DECEBALUS_MASTER_KEY", key_hex)
        .output()
        .expect("failed to run binary");
    assert!(ok.status.success(), "stderr: {}", String::from_utf8_lossy(&ok.stderr));
    assert_eq!(ok.stdout, plaintext);

    // Wrong master key: fails cleanly instead of returning garbage.
    let bad = Command::new(env!("CARGO_BIN_EXE_decebalus-backend"))
        .args(["loot", "decrypt", loot_path.to_str().unwrap()])
        .env("DECEBALUS_MASTER_KEY", "22".repeat(32))
        .output()
        .expect("failed to run binary");
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("decrypt failed"));

    let _ = std::fs::remove_dir_all(&loot_root);
    let _ = std::fs::remove_dir_all(&data_dir);
}
