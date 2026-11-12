//! P3-2 (US-2 AC4) and P3-4 (US-4 AC4): `get` and `inject` refuse to write to
//! a regular file, before they resolve anything.

use std::fs::{self, File, OpenOptions};
use std::process::Stdio;

use crate::common::cli::{Ran, Sandbox, run_to_end};

/// Runs `vaultline --passphrase-stdin <args>` with standard output going to
/// `file`, which is what `> file` does.
fn with_stdout_to(sb: &Sandbox, args: &[&str], stdin: &[u8], file: File) -> Ran {
    let mut command = sb.command();
    command
        .arg("--passphrase-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped());
    let ran = run_to_end(command, stdin);
    sb.assert_no_leak(&ran);
    ran
}

fn passphrase_line(sb: &Sandbox) -> Vec<u8> {
    format!("{}\n", sb.passphrase).into_bytes()
}

/// US-2 AC4.
#[test]
fn get_to_a_regular_file_is_refused_and_the_file_stays_empty() {
    let sb = Sandbox::with_vault();
    sb.secret("out", "demo", "api", "key");
    let path = sb.work.join("out.txt");
    let ran = with_stdout_to(
        &sb,
        &["get", "demo/api/key"],
        &passphrase_line(&sb),
        File::create(&path).unwrap(),
    );
    ran.fails_with("regular file");
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
}

/// US-4 AC4.
#[test]
fn inject_to_a_regular_file_is_refused_and_the_file_stays_empty() {
    let sb = Sandbox::with_vault();
    sb.secret("out", "demo", "api", "key");
    let path = sb.work.join("config.yml");
    let template = sb.work.join("config.tpl");
    fs::write(&template, "key: {{ vault://demo/api/key }}\n").unwrap();
    let ran = with_stdout_to(
        &sb,
        &["inject", "-i", template.to_str().unwrap()],
        &passphrase_line(&sb),
        File::create(&path).unwrap(),
    );
    ran.fails_with("regular file");
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    // The same with the template on standard input.
    let mut stdin = passphrase_line(&sb);
    stdin.extend_from_slice(b"key: {{ vault://demo/api/key }}\n");
    let ran = with_stdout_to(&sb, &["inject"], &stdin, File::create(&path).unwrap());
    ran.fails_with("regular file");
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
}

/// "Before resolving anything": with no vault and no passphrase, the first
/// thing to fail is the check on standard output.
#[test]
fn the_check_comes_before_the_passphrase_and_the_vault() {
    let sb = Sandbox::new();
    let path = sb.work.join("out.txt");
    for args in [&["get", "demo/api/key"][..], &["inject"]] {
        let ran = with_stdout_to(&sb, args, b"", File::create(&path).unwrap());
        ran.fails_with("regular file");
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
}

/// `>>` makes a regular file too.
#[test]
fn appending_to_a_file_is_refused_too() {
    let sb = Sandbox::with_vault();
    sb.secret("out", "demo", "api", "key");
    let path = sb.work.join("log.txt");
    fs::write(&path, "existing\n").unwrap();
    let file = OpenOptions::new().append(true).open(&path).unwrap();
    with_stdout_to(&sb, &["get", "demo/api/key"], &passphrase_line(&sb), file)
        .fails_with("regular file");
    assert_eq!(fs::read_to_string(&path).unwrap(), "existing\n");
}

/// The refusal says why and what to do instead.
#[test]
fn the_error_explains_what_to_do() {
    let sb = Sandbox::new();
    let ran = with_stdout_to(
        &sb,
        &["get", "demo/api/key"],
        b"",
        File::create(sb.work.join("x")).unwrap(),
    );
    let stderr = ran.stderr_str();
    assert!(stderr.contains("written to disk"), "{stderr}");
    assert!(stderr.contains("pipe"), "{stderr}");
}

/// Devices, pipes and terminals are fine: only regular files are refused.
#[test]
fn a_device_is_not_refused() {
    let sb = Sandbox::with_vault();
    let value = sb.secret("out", "demo", "api", "key");
    let null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    with_stdout_to(&sb, &["get", "demo/api/key"], &passphrase_line(&sb), null).ok();
    // A pipe is the usual case, and what every other test uses.
    let ran = sb.run_pass(&["get", "demo/api/key"], b"");
    assert_eq!(ran.stdout_str(), value);
}
