//! P3-4 (US-4 AC1, AC2, AC3, AC5): `vaultline inject`.

use std::fs;

use crate::common::cli::Sandbox;

fn template_file(sb: &Sandbox, text: &str) -> String {
    let path = sb.work.join("template.tpl");
    fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

/// AC1: tags are replaced, whitespace inside the braces is optional, and
/// everything else is copied unchanged.
#[test]
fn tags_are_replaced_and_everything_else_is_copied_unchanged() {
    let sb = Sandbox::with_vault();
    let password = sb.secret("pw", "demo", "db", "password");
    let user = sb.secret("user", "demo", "db", "user");
    let template = "host: db.internal\n\
         user: {{ vault://demo/db/user }}\n\
         password: {{vault://demo/db/password}}\n\
         spaced: {{   vault://demo/db/password\t}}\n\
         url: postgres://{{vault://demo/db/user}}:{{ vault://demo/db/password }}@db/app\n\
         helm: {{ .Values.name }} {{- if .x -}} {{ end }}\n\
         text: vault://demo/db/password is not a tag\n\
         braces: { } {{ }} {{{ vault://demo/db/user }}\n";
    let expected = format!(
        "host: db.internal\n\
         user: {user}\n\
         password: {password}\n\
         spaced: {password}\n\
         url: postgres://{user}:{password}@db/app\n\
         helm: {{{{ .Values.name }}}} {{{{- if .x -}}}} {{{{ end }}}}\n\
         text: vault://demo/db/password is not a tag\n\
         braces: {{ }} {{{{ }}}} {{{user}\n"
    );
    let ran = sb.run_pass(&["inject", "-i", &template_file(&sb, template)], b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), expected);
}

/// The output is exactly the template with the values in: no newline is added
/// and a value's own newline is kept.
#[test]
fn nothing_is_added_and_values_are_inserted_as_they_are() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "multi", b"line one\nline two\n");
    let ran = sb.run_pass(
        &[
            "inject",
            "-i",
            &template_file(&sb, "<{{vault://demo/api/multi}}>"),
        ],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout, b"<line one\nline two\n>");
}

/// AC5: without `-i` the template is read from stdin, after the passphrase line.
#[test]
fn without_i_the_template_is_read_from_stdin() {
    let sb = Sandbox::with_vault();
    let value = sb.secret("key", "demo", "api", "key");
    let ran = sb.run_pass(&["inject"], b"key={{ vault://demo/api/key }}\n");
    ran.ok();
    assert_eq!(ran.stdout_str(), format!("key={value}\n"));
}

#[test]
fn the_same_reference_may_appear_many_times() {
    let sb = Sandbox::with_vault();
    let value = sb.secret("key", "demo", "api", "key");
    let ran = sb.run_pass(
        &["inject"],
        b"{{vault://demo/api/key}}{{vault://demo/api/key}} {{ vault://demo/api/key }}",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), format!("{value}{value} {value}"));
}

/// AC3: a missing reference fails and nothing is printed, not even the text
/// before it.
#[test]
fn a_missing_reference_fails_and_prints_nothing() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "api", "key");
    let template = "before {{ vault://demo/api/key }} then {{ vault://demo/api/missing }} after";
    let ran = sb.run_pass(&["inject", "-i", &template_file(&sb, template)], b"");
    ran.fails_with("vault://demo/api/missing");
    assert!(ran.stderr_str().contains("nothing was written"));
    assert!(ran.stdout.is_empty(), "stdout: {}", ran.stdout_str());
}

/// AC2: a malformed tag fails with its line and column, and nothing is printed.
#[test]
fn a_malformed_tag_fails_with_its_line_and_column() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "api", "key");
    for (template, position) in [
        (
            "line one\nline two {{ vault://demo/api }} end\n",
            "line 2, column 10",
        ),
        ("{{ vault://demo/api/key/extra }}", "line 1, column 1"),
        (
            "ok {{ vault://demo/api/key }}\n\n  {{vault://bad name/x/y}}",
            "line 3, column 3",
        ),
        ("{{ vault://demo/api/key", "line 1, column 1"),
        ("a {{ vault://demo/api/key } }", "line 1, column 3"),
    ] {
        let ran = sb.run_pass(&["inject", "-i", &template_file(&sb, template)], b"");
        ran.fails_with(position);
        assert!(ran.stdout.is_empty(), "{template:?}");
    }
}

/// The template is parsed before the passphrase is read, so a typo costs
/// nothing: with no passphrase on stdin, the error is still the template's.
#[test]
fn the_template_is_checked_before_the_passphrase_is_read() {
    let sb = Sandbox::with_vault();
    let ran = sb.run(
        &["inject", "-i", &template_file(&sb, "{{ vault://oops }}")],
        b"",
    );
    ran.fails_with("line 1, column 1");
}

/// Same, on stdin: the passphrase is the first line, then the template.
#[test]
fn a_malformed_template_on_stdin_fails_too() {
    let sb = Sandbox::with_vault();
    let ran = sb.run_pass(&["inject"], b"x\n{{ vault://demo }}\n");
    ran.fails_with("line 2, column 1");
    assert!(ran.stdout.is_empty());
}

/// A template with no references needs no vault and no passphrase.
#[test]
fn a_template_without_references_needs_no_passphrase() {
    let sb = Sandbox::new();
    let text = "plain {{ .Values.x }} text\n";
    let ran = sb.run(&["inject", "-i", &template_file(&sb, text)], b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), text);
}

#[test]
fn a_wrong_passphrase_fails_and_prints_nothing() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "api", "key");
    sb.register("wrong-passphrase-fake");
    let ran = sb.run(
        &["inject"],
        b"wrong-passphrase-fake\nplain {{ vault://demo/api/key }}\n",
    );
    ran.fails_with("wrong passphrase");
    assert!(ran.stdout.is_empty());
}

#[test]
fn a_missing_template_file_is_reported() {
    let sb = Sandbox::with_vault();
    sb.run_pass(&["inject", "-i", "no-such-file.tpl"], b"")
        .fails_with("can't read the template");
}

#[test]
fn a_template_may_hold_any_bytes() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "key", b"V");
    let mut stdin = format!("{}\n", sb.passphrase).into_bytes();
    stdin.extend_from_slice(b"\xff\x00{{vault://demo/api/key}}\xfe");
    let ran = sb.run(&["inject"], &stdin);
    ran.ok();
    assert_eq!(ran.stdout, b"\xff\x00V\xfe");
}
