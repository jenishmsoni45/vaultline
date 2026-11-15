//! The scripts that produce the README's numbers (P5-3, D-006, D-058): the
//! counters are tested on made-up input, and `numbers.sh` is checked for its
//! refusals. The benchmarks themselves are run by `make bench`, never here.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}

fn sh(name: &str, args: &[&Path]) -> Output {
    Command::new("sh")
        .arg(script(name))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("sh should start")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A target's `fuzz-time-<target>` directory with an exit status.
fn target(root: &Path, name: &str, status: Option<&str>) {
    let dir = root.join(format!("fuzz-time-{name}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("seconds"), "20401\n").unwrap();
    fs::write(dir.join("cores"), "4\n").unwrap();
    if let Some(status) = status {
        fs::write(dir.join("exit-status"), format!("{status}\n")).unwrap();
    }
}

/// A `fuzz-crashes-<target>` directory holding these files.
fn crashes(root: &Path, name: &str, files: &[&str]) {
    let dir = root.join(format!("fuzz-crashes-{name}"));
    fs::create_dir_all(&dir).unwrap();
    for file in files {
        fs::write(dir.join(file), b"fake fuzz input").unwrap();
    }
}

#[test]
fn the_crash_script_counts_targets_clean_exits_and_crash_files() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, status) in [("vault_file", "0"), ("template", "0"), ("reference", "77")] {
        target(tmp.path(), name, Some(status));
    }
    crashes(
        tmp.path(),
        "reference",
        &["crash-aaa", "oom-bbb", "timeout-ccc", "leak-ddd"],
    );
    // Other files a fuzzer leaves are not crashes.
    crashes(tmp.path(), "template", &["slow-unit-eee", "notes.txt"]);

    let out = sh("fuzz-crashes.sh", &[tmp.path()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "targets: 3\nclean: 2\ncrashes: 4\n");
}

#[test]
fn a_campaign_with_no_crash_directories_has_none() {
    let tmp = tempfile::tempdir().unwrap();
    target(tmp.path(), "vault_file", Some("0"));
    let out = sh("fuzz-crashes.sh", &[tmp.path()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "targets: 1\nclean: 1\ncrashes: 0\n");
}

#[test]
fn the_crash_script_never_counts_a_missing_status_as_clean() {
    let tmp = tempfile::tempdir().unwrap();
    target(tmp.path(), "vault_file", None);
    let out = sh("fuzz-crashes.sh", &[tmp.path()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("exit-status"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
}

#[test]
fn the_crash_script_refuses_an_empty_campaign_and_bad_usage() {
    let tmp = tempfile::tempdir().unwrap();
    let out = sh("fuzz-crashes.sh", &[tmp.path()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("no fuzz-time-"), "{}", stderr(&out));

    let out = sh("fuzz-crashes.sh", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("usage"), "{}", stderr(&out));
}

fn count_tests(input: &str) -> Output {
    let mut child = Command::new("sh")
        .arg(script("count-tests.sh"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sh should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn the_test_counter_sums_every_binary() {
    let out = count_tests(
        "running 3 tests\n\
         test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n\
         \n\
         running 40 tests\n\
         test result: ok. 38 passed; 1 failed; 2 ignored; 0 measured; 0 filtered out; finished in 9.2s\n\
         test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "passed=41 failed=1 ignored=2\n");
}

#[test]
fn the_test_counter_gives_no_count_for_input_without_results() {
    let out = count_tests("error: could not compile `vaultline`\n");
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).is_empty());
    assert!(
        stderr(&out).contains("no \"test result:\""),
        "{}",
        stderr(&out)
    );
}

/// `numbers.sh` refuses bad arguments before it runs a benchmark or a test.
#[test]
fn numbers_refuses_bad_arguments_before_measuring_anything() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-directory");
    let cases: Vec<Vec<&Path>> = vec![
        vec![],
        vec![Path::new("--run")],
        vec![Path::new("--run"), Path::new("not-a-number")],
        vec![Path::new("--campaign"), missing.as_path()],
        vec![Path::new("--other"), Path::new("1")],
    ];
    for args in cases {
        let out = sh("numbers.sh", &args);
        assert_eq!(out.status.code(), Some(1), "arguments {args:?}");
        assert!(stderr(&out).contains("usage"), "{}", stderr(&out));
        assert!(stdout(&out).is_empty());
    }
}

/// Every script that makes a number is executable, and `make bench` runs both
/// benchmarks.
#[test]
fn the_number_scripts_exist_and_make_bench_runs_both_benchmarks() {
    use std::os::unix::fs::PermissionsExt;
    for name in [
        "bench-unlock.sh",
        "bench-run-overhead.sh",
        "fuzz-cpu-hours.sh",
        "fuzz-crashes.sh",
        "count-tests.sh",
        "numbers.sh",
    ] {
        let mode = fs::metadata(script(name))
            .unwrap_or_else(|e| panic!("scripts/{name}: {e}"))
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "scripts/{name} is not executable");
    }
    let makefile =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile")).unwrap();
    let bench = &makefile[makefile.find("\nbench:").expect("a bench target")..];
    assert!(bench.contains("sh scripts/bench-unlock.sh"));
    assert!(bench.contains("sh scripts/bench-run-overhead.sh"));
}
