//! Phase 5's documentation criteria (`docs/phases.md`): P5-3, P5-4 and P5-5.
//!
//! P5-3: a measured number in the README or the Phase 5 docs names a script in
//! `scripts/` (D-006). P5-4: the README's security section states exactly the
//! claims in `threat-model.md` §7, each linked to its tests. P5-5: the
//! postmortem, the talk outline and the demo script exist, and the two time
//! budgets add up.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// The text of the `## <heading>` section, up to the next `## ` heading.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(&format!("\n## {heading}"))
        .unwrap_or_else(|| panic!("no section {heading:?}"));
    let body = &doc[start + 1..];
    let after = body.find('\n').map_or(body.len(), |n| n + 1);
    match body[after..].find("\n## ") {
        Some(end) => &body[..after + end],
        None => body,
    }
}

/// The cells of every table row in `text` that has `columns` cells, without the
/// header and the separator.
fn rows(text: &str, columns: usize) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| l.starts_with('|'))
        .map(|l| {
            // `\|` is a pipe inside a cell, not a cell border.
            l.replace("\\|", "\u{1}")
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().replace('\u{1}', "|"))
                .collect::<Vec<_>>()
        })
        .filter(|cells| cells.len() == columns)
        .filter(|cells| {
            !cells
                .iter()
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
        })
        .skip(1)
        .collect()
}

/// The targets of every markdown link `[text](target)` in `text`.
fn link_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("](") {
        let after = &rest[open + 2..];
        match after.find(')') {
            Some(close) => {
                targets.push(after[..close].to_string());
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    targets
}

/// The test files `threat-model.md` §7 names in its "Proven by" column, as paths
/// from the repository root: `S1` to `S9` are the invariant files, `S10` is the
/// fuzz targets, and `` `dir/file.rs` `` is under `tests/`.
fn proof_files(proof: &str) -> Vec<String> {
    const INVARIANTS: [&str; 9] = [
        "s1_roundtrip",
        "s2_tamper",
        "s3_swap",
        "s4_wrong_passphrase",
        "s5_fixtures",
        "s6_no_plaintext_on_disk",
        "s7_masking",
        "s8_audit_tamper",
        "s9_agent",
    ];
    let mut files = Vec::new();
    for token in proof.split(|c: char| !c.is_alphanumeric() && c != '/' && c != '_' && c != '.') {
        if let Some(n) = token
            .strip_prefix('S')
            .and_then(|n| n.parse::<usize>().ok())
        {
            if n == 10 {
                files.push("fuzz/fuzz_targets/".to_string());
            } else if (1..=9).contains(&n) {
                files.push(format!("tests/invariants/{}.rs", INVARIANTS[n - 1]));
            }
        } else if token.ends_with(".rs") && token.contains('/') {
            files.push(format!("tests/{token}"));
        }
    }
    files
}

/// The §7 table: `(id, claim, proven by)`.
fn claims() -> Vec<(String, String, String)> {
    let model = read("docs/threat-model.md");
    rows(
        section(&model, "7. Claims and the tests that prove them"),
        3,
    )
    .into_iter()
    .map(|c| (c[0].clone(), c[1].clone(), c[2].clone()))
    .collect()
}

/// Whether a line states a measurement: a number followed by `ms`, `CPU-hours`
/// or `crashes`.
fn states_a_measurement(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if !c.is_ascii_digit() || (i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '.'))
        {
            continue;
        }
        let mut j = i;
        while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.' || chars[j] == ',') {
            j += 1;
        }
        while j < chars.len() && chars[j] == ' ' {
            j += 1;
        }
        let rest: String = chars[j..].iter().collect();
        let word_end = |word: &str| {
            rest.starts_with(word)
                && !rest[word.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric())
        };
        if word_end("ms") || word_end("CPU-hours") || word_end("crashes") {
            return true;
        }
    }
    false
}

#[test]
fn the_phase_5_docs_exist() {
    for (path, title) in [
        ("docs/postmortem.md", "# Postmortem"),
        ("docs/talk-outline.md", "# Talk outline"),
        ("docs/demo-script.md", "# Demo script"),
    ] {
        let text = read(path);
        assert!(
            text.starts_with(title),
            "{path} should start with {title:?}"
        );
        assert!(text.lines().count() > 20, "{path} looks empty");
    }
}

#[test]
fn the_talk_outline_adds_up_to_twenty_minutes() {
    let outline = read("docs/talk-outline.md");
    let table = rows(section(&outline, "Sections"), 3);
    assert!(table.len() >= 5, "the outline has too few sections");
    let minutes: u32 = table
        .iter()
        .map(|c| {
            c[2].parse::<u32>()
                .unwrap_or_else(|_| panic!("minutes: {c:?}"))
        })
        .sum();
    assert_eq!(minutes, 20);
    // Each section in the table has a heading below, with the same number and
    // the same minutes.
    for cells in &table {
        let start = format!("## {}. ", cells[0]);
        let end = format!("({} min)", cells[2]);
        assert!(
            outline
                .lines()
                .any(|l| l.starts_with(&start) && l.ends_with(&end)),
            "no heading {start:?}...{end:?}"
        );
    }
}

#[test]
fn the_demo_script_adds_up_to_three_minutes_and_each_shot_starts_when_the_last_ends() {
    let script = read("docs/demo-script.md");
    let table = rows(section(&script, "Shots"), 5);
    assert!(table.len() >= 5, "the script has too few shots");
    let mut elapsed = 0u32;
    for cells in &table {
        let (minutes, seconds) = cells[1].split_once(':').expect("a start time m:ss");
        let start = minutes.parse::<u32>().unwrap() * 60 + seconds.parse::<u32>().unwrap();
        assert_eq!(start, elapsed, "shot {} starts at {}", cells[0], cells[1]);
        let length = cells[2].strip_suffix(" s").expect("a length in seconds");
        elapsed += length.parse::<u32>().unwrap();
    }
    assert_eq!(elapsed, 180, "the shots must add up to 3 minutes");
}

/// Every test file §7 names exists, so the claims table can't point at nothing.
#[test]
fn every_test_named_in_the_threat_model_exists() {
    let claims = claims();
    assert_eq!(claims.len(), 13, "C1 to C13");
    for (id, _, proof) in &claims {
        let files = proof_files(proof);
        assert!(!files.is_empty(), "{id} names no test file: {proof}");
        for file in files {
            assert!(root().join(&file).exists(), "{id}: {file} does not exist");
        }
    }
}

/// P5-4: the README's security table has exactly the claims of §7, in the same
/// words, and links the same tests.
#[test]
fn the_readme_states_only_the_threat_model_claims_and_links_their_tests() {
    let readme = read("README.md");
    let table = rows(section(&readme, "Security model"), 3);
    let claims = claims();
    assert_eq!(
        table.iter().map(|c| c[0].as_str()).collect::<Vec<_>>(),
        claims.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
        "the README's claims must be C1 to C13, in order"
    );
    for (cells, (id, claim, proof)) in table.iter().zip(&claims) {
        assert_eq!(
            &cells[1], claim,
            "{id}: the claim differs from threat-model.md"
        );
        let linked = link_targets(&cells[2]);
        for file in proof_files(proof) {
            assert!(
                linked.contains(&file),
                "{id}: the README doesn't link {file}"
            );
        }
        for target in linked {
            assert!(
                root().join(&target).exists(),
                "{id}: {target} does not exist"
            );
        }
    }
}

/// P5-3: each row of the README's numbers table names a script that exists and
/// holds a result.
#[test]
fn every_number_in_the_readme_names_a_script_and_has_a_value() {
    let readme = read("README.md");
    let numbers = section(&readme, "Numbers");
    let table = rows(numbers, 3);
    assert!(
        table.len() >= 5,
        "unlock, run overhead, CPU-hours, crashes, tests"
    );
    for cells in &table {
        let script = cells[2].trim_matches('`');
        assert!(
            script.starts_with("scripts/") && script.ends_with(".sh"),
            "{}: names no script: {}",
            cells[0],
            cells[2]
        );
        assert!(root().join(script).exists(), "{} does not exist", script);
        assert!(
            cells[1].chars().any(|c| c.is_ascii_digit()),
            "{}: no result: {}",
            cells[0],
            cells[1]
        );
        assert!(
            !cells[1].contains("TO BE FILLED"),
            "{} has no result yet",
            cells[0]
        );
    }
    assert!(
        numbers.contains("scripts/numbers.sh"),
        "the section should say that numbers.sh collects them"
    );
}

/// P5-3, from the other side: no measurement is stated outside the README's
/// numbers table. A target or a parameter is labelled as one.
#[test]
fn no_measurement_is_stated_outside_the_numbers_table() {
    let readme = read("README.md");
    let numbers = section(&readme, "Numbers");
    let outside_numbers = readme.replace(numbers, "");
    let docs = [
        ("README.md (outside Numbers)", outside_numbers),
        ("docs/postmortem.md", read("docs/postmortem.md")),
        ("docs/talk-outline.md", read("docs/talk-outline.md")),
        ("docs/demo-script.md", read("docs/demo-script.md")),
    ];
    for (name, text) in &docs {
        for line in text.lines() {
            let labelled = line.contains("target") || line.contains("parameter");
            assert!(
                !states_a_measurement(line) || labelled,
                "{name} states a measurement that no script produced: {line}"
            );
        }
    }
}

#[test]
fn the_measurement_detector_finds_what_it_should() {
    assert!(states_a_measurement("it takes 16 ms"));
    assert!(states_a_measurement("it takes 16.5 ms."));
    assert!(states_a_measurement("about 20 CPU-hours"));
    assert!(states_a_measurement("found 3 crashes"));
    assert!(!states_a_measurement("5 h 40 min"));
    assert!(!states_a_measurement("a 103-byte path and 256 MiB"));
    assert!(!states_a_measurement("D-051 and NFR-9"));
    assert!(!states_a_measurement("the arms of the harms"));
}
