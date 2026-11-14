//! S6 (`docs/design.md` §2, §12.3), P3-7: `run` and `inject` never write a
//! secret to the filesystem.
//!
//! The scan covers every place vaultline could write: `HOME`, `TMPDIR`,
//! `VAULTLINE_DIR` and the working directory are all inside one fresh
//! temporary directory, and every file under it is searched for each secret
//! as it is and hex-encoded. It can't say anything about the rest of the disk;
//! the design guarantees by construction that vaultline writes only inside
//! `VAULTLINE_DIR` (`docs/architecture.md` §7).
//!
//! §12.3 asks for every command both in-process and through an agent: the first
//! test is in-process, the second goes through an unlocked agent, and both end
//! with the same scan.
//!
//! `rotate` is part of §12.3's list. It always runs Argon2id at the default
//! parameters (D-040), so it runs once per phase that tests it, in
//! `tests/cli/passwd_rotate.rs`, and that test ends with the same scan. It
//! never goes through the agent.

use std::fs::{self, File};
use std::process::Stdio;

use crate::common::cli::{PASSPHRASE, Sandbox, assert_no_plaintext_under, files_under, run_to_end};

fn env_ref(sb: &Sandbox, reference: &str, args: &[&str]) -> crate::common::cli::Ran {
    let mut command = sb.command();
    command
        .env("API", reference)
        .arg("--passphrase-stdin")
        .arg("run")
        .args(args);
    sb.run_command(command, format!("{}\n", sb.passphrase).as_bytes())
}

#[test]
fn no_command_writes_a_secret_or_the_passphrase_to_disk() {
    let sb = Sandbox::with_vault();
    let stored = sb.secret("stored", "demo", "api", "key");
    let typed = crate::common::marker("typed");
    sb.register(&typed);

    // `set`.
    sb.run_pass(&["set", "demo/api/typed"], format!("{typed}\n").as_bytes())
        .ok();

    // `run`, with a child that prints its secret to both streams, masked and
    // with --no-mask.
    let print = ["--", "sh", "-c", "echo \"$API\"; echo \"$API\" >&2"];
    env_ref(&sb, "vault://demo/api/key", &print).ok();
    // Unmasked, the child's own output holds the secret, so it goes to stdout
    // only: stderr is checked for leaks after every command.
    env_ref(
        &sb,
        "vault://demo/api/typed",
        &["--no-mask", "--", "sh", "-c", "echo \"$API\""],
    )
    .ok();

    // `run` with an env file that holds references, not secrets.
    fs::write(sb.work.join("app.env"), "FROM_FILE=vault://demo/api/key\n").unwrap();
    env_ref(
        &sb,
        "vault://demo/api/typed",
        &[
            "--env-file",
            "app.env",
            "--",
            "sh",
            "-c",
            "echo \"$FROM_FILE $API\"",
        ],
    )
    .ok();

    // `inject` and `get` into a pipe.
    let ran = sb.run_pass(&["inject"], b"key={{ vault://demo/api/key }}\n");
    assert_eq!(ran.stdout_str(), format!("key={stored}\n"));
    let ran = sb.run_pass(&["get", "demo/api/typed"], b"");
    assert_eq!(ran.stdout_str(), typed);

    // `list` and `rm`.
    sb.run_pass(&["list"], b"").ok();
    sb.run_pass(&["rm", "demo/api/typed"], b"").ok();

    assert_no_plaintext_under(&[sb.tmp.path()], &[&stored, &typed, PASSPHRASE]);
    // The vault is where the data went: ciphertext only.
    assert!(sb.vault_path().is_file());
}

/// The same commands through an unlocked agent (§12.3 step 2). The agent holds
/// the key and decrypts, and its socket and lock files are in the scanned
/// directory too. Neither the secrets nor the passphrase reach any file.
#[test]
fn no_command_writes_a_secret_or_the_passphrase_to_disk_through_an_agent() {
    let sb = Sandbox::with_vault();
    let stored = sb.secret("stored", "demo", "api", "key");
    let typed = crate::common::marker("typed");
    sb.register(&typed);
    sb.unlock(&[]).ok();
    assert!(sb.socket().exists(), "the agent is up");

    sb.run_pass(&["set", "demo/api/typed"], format!("{typed}\n").as_bytes())
        .ok();
    let print = ["--", "sh", "-c", "echo \"$API\"; echo \"$API\" >&2"];
    env_ref(&sb, "vault://demo/api/key", &print).ok();
    env_ref(
        &sb,
        "vault://demo/api/typed",
        &["--no-mask", "--", "sh", "-c", "echo \"$API\""],
    )
    .ok();
    fs::write(sb.work.join("app.env"), "FROM_FILE=vault://demo/api/key\n").unwrap();
    env_ref(
        &sb,
        "vault://demo/api/typed",
        &["--env-file", "app.env", "--", "sh", "-c", "echo \"$FROM_FILE $API\""],
    )
    .ok();
    let ran = sb.run_pass(&["inject"], b"key={{ vault://demo/api/key }}\n");
    assert_eq!(ran.stdout_str(), format!("key={stored}\n"));
    let ran = sb.run_pass(&["get", "demo/api/typed"], b"");
    assert_eq!(ran.stdout_str(), typed);
    sb.run_pass(&["list"], b"").ok();
    sb.run_pass(&["rm", "demo/api/typed"], b"").ok();
    sb.run_pass(&["audit", "verify"], b"").ok();

    // While the agent still holds the key, and after it has let go.
    assert_no_plaintext_under(&[sb.tmp.path()], &[&stored, &typed, PASSPHRASE]);
    sb.run(&["agent", "stop"], b"").ok();
    assert_no_plaintext_under(&[sb.tmp.path()], &[&stored, &typed, PASSPHRASE]);
}

/// §12.3 step 4: `inject > file` and `get > file` are refused and leave the
/// file empty.
#[test]
fn redirecting_to_a_file_is_refused_and_leaves_the_file_empty() {
    let sb = Sandbox::with_vault();
    let stored = sb.secret("stored", "demo", "api", "key");
    for (name, args, extra) in [
        ("get.out", vec!["get", "demo/api/key"], ""),
        (
            "inject.out",
            vec!["inject"],
            "key={{ vault://demo/api/key }}\n",
        ),
    ] {
        let path = sb.work.join(name);
        let mut command = sb.command();
        command
            .arg("--passphrase-stdin")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(File::create(&path).unwrap()))
            .stderr(Stdio::piped());
        let stdin = format!("{}\n{extra}", sb.passphrase);
        let ran = run_to_end(command, stdin.as_bytes());
        sb.assert_no_leak(&ran);
        ran.fails_with("regular file");
        assert_eq!(fs::metadata(&path).unwrap().len(), 0, "{name}");
    }
    assert_no_plaintext_under(&[sb.tmp.path()], &[&stored]);
}

/// The scan must be able to fail: a secret planted raw, or hex-encoded in
/// either case, is found.
#[test]
fn the_scan_finds_a_planted_secret_raw_or_hex_encoded() {
    let secret = "fake-planted-secret-0123";
    let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
    for contents in [
        format!("before {secret} after"),
        format!("hex {hex}"),
        format!("HEX {}", hex.to_ascii_uppercase()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        fs::write(dir.path().join("nested").join("file"), contents).unwrap();
        let found = std::panic::catch_unwind(|| {
            assert_no_plaintext_under(&[dir.path()], &[secret]);
        });
        assert!(found.is_err(), "the scan missed a planted secret");
    }
    let clean = tempfile::tempdir().unwrap();
    fs::write(clean.path().join("file"), "nothing to see").unwrap();
    assert_no_plaintext_under(&[clean.path()], &[secret]);
    assert_eq!(files_under(&[clean.path()]).len(), 1);
}
