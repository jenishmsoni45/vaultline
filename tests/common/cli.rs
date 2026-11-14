//! Running the built `vaultline` binary in a sandbox (`docs/design.md` §12.1,
//! §12.2).
//!
//! Every [`Sandbox`] is a fresh temporary directory holding the vault
//! directory, `HOME`, `TMPDIR` and the working directory, and each command runs
//! with an empty environment apart from those and `PATH`. Nothing outside the
//! temporary directory is touched.
//!
//! Safety rules the helpers enforce:
//!
//! - Passphrases always come from standard input (`--passphrase-stdin`). A test
//!   never reaches the terminal prompt, so a test can't wait for a person.
//! - A command that doesn't finish within [`TIMEOUT`] is killed and the test
//!   fails, so nothing is left running.
//! - After every command, stderr is checked for the passphrase and for every
//!   fake secret the test registered (`docs/phases.md` rule 4).
//! - Every agent a sandbox starts is stopped when the sandbox is dropped, and
//!   the drop waits for the process to exit, so a test never leaves an agent
//!   behind, even when it fails (`docs/design.md` §12.2, NFR-17).

#![allow(dead_code)]

use std::cell::RefCell;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tempfile::TempDir;
use vaultline::vault::{KdfParams, Vault};

use super::{CHEAP, contains, marker, name, pass, value};

/// How long one command may run before it is killed.
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// A passphrase that passes the 12-character rule.
pub const PASSPHRASE: &str = "fake-passphrase-for-tests";

/// Held by every test that runs `passwd` or `rotate`, which always write the
/// default 256 MiB Argon2id parameters (D-040), so that they never run at the
/// same time.
pub static HEAVY: Mutex<()> = Mutex::new(());

/// The result of one command.
pub struct Ran {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Ran {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Asserts exit code 0.
    pub fn ok(&self) -> &Ran {
        assert_eq!(self.code, Some(0), "stderr: {}", self.stderr_str());
        self
    }

    /// Asserts exit code `code`.
    pub fn code(&self, code: i32) -> &Ran {
        assert_eq!(
            self.code,
            Some(code),
            "stdout: {}\nstderr: {}",
            self.stdout_str(),
            self.stderr_str()
        );
        self
    }

    /// Asserts exit code 1 (a vaultline error) and that stderr says `text`.
    pub fn fails_with(&self, text: &str) -> &Ran {
        self.code(1);
        assert!(
            self.stderr_str().contains(text),
            "expected stderr to contain {text:?}, got: {}",
            self.stderr_str()
        );
        self
    }
}

/// A fresh vault directory, home, temporary directory and working directory.
pub struct Sandbox {
    pub tmp: TempDir,
    /// `VAULTLINE_DIR`. Not created until a vault is.
    pub dir: PathBuf,
    pub home: PathBuf,
    pub tmpdir: PathBuf,
    pub work: PathBuf,
    pub passphrase: String,
    vault: Option<Vault>,
    secrets: RefCell<Vec<String>>,
    /// Every agent this sandbox started, stopped again on drop.
    agents: RefCell<Vec<Pid>>,
}

impl Sandbox {
    /// A sandbox with no vault.
    pub fn new() -> Sandbox {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = tmp.path().canonicalize().expect("the temporary directory");
        let make = |sub: &str| {
            let path = root.join(sub);
            fs::create_dir(&path).expect("a sandbox directory");
            path
        };
        let home = make("home");
        let tmpdir = make("tmp");
        let work = make("work");
        let sandbox = Sandbox {
            dir: root.join("vaultline"),
            home,
            tmpdir,
            work,
            tmp,
            passphrase: PASSPHRASE.to_string(),
            vault: None,
            secrets: RefCell::new(Vec::new()),
            agents: RefCell::new(Vec::new()),
        };
        sandbox.register(PASSPHRASE);
        sandbox
    }

    /// A sandbox with an empty vault that uses the cheap Argon2id parameters
    /// (D-020), created through the library like any other vault.
    pub fn with_vault() -> Sandbox {
        Self::with_vault_params(CHEAP)
    }

    /// A sandbox whose vault directory has this single-component name, for
    /// tests that need a long path (the socket's path is limited).
    pub fn with_vault_in(dir_name: &str) -> Sandbox {
        let mut sandbox = Self::new();
        sandbox.dir = sandbox
            .tmp
            .path()
            .canonicalize()
            .expect("the sandbox")
            .join(dir_name);
        sandbox.vault = Some(
            Vault::create(&sandbox.dir, &pass(&sandbox.passphrase), CHEAP).expect("a new vault"),
        );
        sandbox
    }

    pub fn with_vault_params(kdf: KdfParams) -> Sandbox {
        let mut sandbox = Self::new();
        sandbox.vault = Some(
            Vault::create(&sandbox.dir, &pass(&sandbox.passphrase), kdf).expect("a new vault"),
        );
        sandbox
    }

    /// Stores a value through the library.
    pub fn set(&self, project: &str, item: &str, field: &str, bytes: &[u8]) {
        self.vault
            .as_ref()
            .expect("a sandbox with a vault")
            .set(&name(project), &name(item), &name(field), &value(bytes))
            .expect("set");
    }

    /// Makes up a fake secret, registers it for the stderr check, and stores it.
    pub fn secret(&self, tag: &str, project: &str, item: &str, field: &str) -> String {
        let secret = marker(tag);
        self.register(&secret);
        self.set(project, item, field, secret.as_bytes());
        secret
    }

    /// Adds a string that no command may print to stderr.
    pub fn register(&self, secret: &str) {
        // The empty string is in every output; there is nothing to protect.
        if !secret.is_empty() {
            self.secrets.borrow_mut().push(secret.to_string());
        }
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir.join("vault")
    }

    pub fn vault_bytes(&self) -> Vec<u8> {
        fs::read(self.vault_path()).expect("the vault file")
    }

    /// The command, with the sandbox environment and nothing else but `PATH`.
    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vaultline"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmpdir)
            .env("VAULTLINE_DIR", &self.dir)
            .current_dir(&self.work);
        command
    }

    /// Runs `vaultline --passphrase-stdin <args>` with `stdin` as the whole of
    /// standard input.
    pub fn run(&self, args: &[&str], stdin: &[u8]) -> Ran {
        let mut command = self.command();
        command.arg("--passphrase-stdin").args(args);
        self.run_command(command, stdin)
    }

    /// The same, with the passphrase as the first line of standard input and
    /// `rest` after it.
    pub fn run_pass(&self, args: &[&str], rest: &[u8]) -> Ran {
        let mut stdin = format!("{}\n", self.passphrase).into_bytes();
        stdin.extend_from_slice(rest);
        self.run(args, &stdin)
    }

    /// Runs a prepared command with `stdin`, waits for it with a time limit,
    /// then checks stderr for leaks.
    pub fn run_command(&self, mut command: Command, stdin: &[u8]) -> Ran {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let ran = run_to_end(command, stdin);
        self.assert_no_leak(&ran);
        ran
    }

    /// Asserts that stderr holds no registered secret.
    pub fn assert_no_leak(&self, ran: &Ran) {
        for secret in self.secrets.borrow().iter() {
            assert!(
                !contains(&ran.stderr, secret.as_bytes()),
                "stderr contains a secret: {}",
                ran.stderr_str().replace(secret.as_str(), "<SECRET>")
            );
        }
    }
}

impl Sandbox {
    /// The agent's socket.
    pub fn socket(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }

    /// `unlock`, with the passphrase on stdin. A started agent is remembered,
    /// so that dropping the sandbox stops it.
    pub fn unlock(&self, extra: &[&str]) -> Ran {
        let mut args = vec!["unlock"];
        args.extend_from_slice(extra);
        let ran = self.run_pass(&args, b"");
        if let Some(pid) = self.agent_pid() {
            let mut agents = self.agents.borrow_mut();
            if !agents.contains(&pid) {
                agents.push(pid);
            }
        }
        ran
    }

    /// The process ID of the agent behind the socket, from the socket's peer
    /// credentials, so that no process-ID file is needed (D-055).
    pub fn agent_pid(&self) -> Option<Pid> {
        peer_pid(&UnixStream::connect(self.socket()).ok()?)
    }

    /// Waits until `condition` holds, for at most 20 seconds.
    pub fn wait_for(&self, what: &str, condition: impl Fn() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "timed out waiting for {what}"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    /// Waits until the agent process has exited and its socket is gone.
    pub fn wait_for_agent_exit(&self, pid: Pid) {
        self.wait_for("the agent to exit", || !is_alive(pid));
        assert!(!self.socket().exists(), "the socket is still there");
    }

    /// Every record of the audit log, decoded.
    pub fn audit_records(&self) -> Vec<vaultline::audit::Record> {
        use vaultline::audit::{HEADER_LEN, RECORD_LEN, Record};
        let log = fs::read(self.dir.join("audit.log")).expect("the audit log");
        log[HEADER_LEN..]
            .chunks(RECORD_LEN)
            .map(|bytes| Record::decode(bytes).expect("a valid record"))
            .collect()
    }

    /// The events of the audit log, in order.
    pub fn audit_events(&self) -> Vec<vaultline::audit::Event> {
        self.audit_records().iter().map(|r| r.event).collect()
    }

    /// The `item_id` of a stored item, read through the library.
    pub fn item_id(&self, project: &str, item: &str) -> [u8; 16] {
        Vault::open(&self.dir, &pass(&self.passphrase))
            .expect("open the vault")
            .items()
            .expect("the items")
            .into_iter()
            .find(|i| i.project == name(project) && i.item == name(item))
            .expect("the item exists")
            .item_id
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        for pid in self.agents.borrow().iter() {
            if !is_alive(*pid) {
                continue;
            }
            let mut command = self.command();
            command
                .args(["agent", "stop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = command.status();
            let started = Instant::now();
            while is_alive(*pid) && started.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(25));
            }
            if is_alive(*pid) {
                let _ = kill(*pid, Signal::SIGKILL);
            }
        }
    }
}

/// Whether a process exists.
pub fn is_alive(pid: Pid) -> bool {
    kill(pid, None).is_ok()
}

/// The process ID of the process at the other end of a Unix socket.
#[cfg(target_os = "linux")]
pub fn peer_pid(stream: &UnixStream) -> Option<Pid> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials)
        .ok()
        .map(|c| Pid::from_raw(c.pid()))
}

#[cfg(not(target_os = "linux"))]
pub fn peer_pid(stream: &UnixStream) -> Option<Pid> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};
    getsockopt(stream, LocalPeerPid).ok().map(Pid::from_raw)
}

/// Spawns, feeds standard input from a thread so a full pipe can't block, and
/// collects the output. A watchdog kills the process if it outlives
/// [`TIMEOUT`].
pub fn run_to_end(mut command: Command, stdin: &[u8]) -> Ran {
    let mut child = command.spawn().expect("the vaultline binary should start");
    let done = watchdog(child.id());
    let mut input = child.stdin.take().expect("a piped stdin");
    let bytes = stdin.to_vec();
    let writer = thread::spawn(move || {
        // The child may exit without reading everything; that is not an error.
        let _ = input.write_all(&bytes);
    });
    let output = child.wait_with_output().expect("the command should finish");
    done.store(true, Ordering::SeqCst);
    let _ = writer.join();
    Ran {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

/// Kills `pid` after [`TIMEOUT`] unless the returned flag is set first.
fn watchdog(pid: u32) -> Arc<AtomicBool> {
    let done = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&done);
    thread::spawn(move || {
        let started = Instant::now();
        while started.elapsed() < TIMEOUT {
            if flag.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if let Ok(pid) = i32::try_from(pid) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    });
    done
}

/// A running `vaultline` that a test talks to while it runs. Dropping it
/// kills the whole process group, so a failing test leaves nothing behind.
pub struct Live {
    pub child: Child,
    pgid: Pid,
    done: Arc<AtomicBool>,
}

impl Live {
    /// Starts the command in its own process group, with all three standard
    /// streams piped.
    pub fn start(mut command: Command) -> Live {
        use std::os::unix::process::CommandExt;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().expect("the vaultline binary should start");
        let pid = i32::try_from(child.id()).expect("a process ID");
        let done = watchdog(child.id());
        Live {
            child,
            pgid: Pid::from_raw(pid),
            done,
        }
    }

    pub fn pid(&self) -> Pid {
        self.pgid
    }

    /// Writes to the command's standard input and keeps it open.
    pub fn write_stdin(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().expect("a piped stdin");
        stdin.write_all(bytes).expect("write to stdin");
        stdin.flush().expect("flush stdin");
    }

    /// Closes the command's standard input.
    pub fn close_stdin(&mut self) {
        drop(self.child.stdin.take());
    }

    /// Reads standard output until `needle` has appeared. Fails after
    /// [`TIMEOUT`] or at the end of the output.
    pub fn read_stdout_until(&mut self, needle: &str) -> String {
        let stdout = self.child.stdout.as_mut().expect("a piped stdout");
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        let started = Instant::now();
        while !contains(&seen, needle.as_bytes()) {
            assert!(
                started.elapsed() < TIMEOUT,
                "timed out waiting for {needle:?}"
            );
            match stdout.read(&mut byte) {
                Ok(0) => panic!(
                    "the output ended before {needle:?}: {}",
                    String::from_utf8_lossy(&seen)
                ),
                Ok(_) => seen.push(byte[0]),
                Err(e) => panic!("reading the output failed: {e}"),
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Sends `signal` to the command alone.
    pub fn signal(&self, signal: Signal) {
        kill(self.pgid, signal).expect("signal the command");
    }

    /// Sends `signal` to every process in the command's group, as the
    /// terminal does for Ctrl-C.
    pub fn signal_group(&self, signal: Signal) {
        nix::sys::signal::killpg(self.pgid, signal).expect("signal the group");
    }

    /// Waits for the command to exit and returns what it left.
    pub fn finish(mut self) -> Ran {
        self.close_stdin();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            let _ = pipe.read_to_end(&mut stdout);
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_end(&mut stderr);
        }
        let status = self.child.wait().expect("the command should finish");
        self.done.store(true, Ordering::SeqCst);
        Ran {
            code: status.code(),
            stdout,
            stderr,
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // Does nothing if the group is already gone.
        let _ = nix::sys::signal::killpg(self.pgid, Signal::SIGKILL);
        let _ = self.child.wait();
        self.done.store(true, Ordering::SeqCst);
    }
}

/// Every file under `roots`, recursively.
pub fn files_under(roots: &[&Path]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    while let Some(path) = pending.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                pending.extend(entries.flatten().map(|e| e.path()));
            }
        } else if meta.is_file() {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// S6 (`docs/design.md` §12.3): asserts that none of `secrets` appears in any
/// file under `roots`, as it is or hex-encoded in either case.
pub fn assert_no_plaintext_under(roots: &[&Path], secrets: &[&str]) {
    for file in files_under(roots) {
        let bytes = fs::read(&file).expect("read a sandbox file");
        for secret in secrets {
            let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
            for needle in [secret.to_string(), hex.clone(), hex.to_ascii_uppercase()] {
                assert!(
                    !contains(&bytes, needle.as_bytes()),
                    "{} holds a secret",
                    file.display()
                );
            }
        }
    }
}
