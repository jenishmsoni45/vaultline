# Postmortem: a claim about `Debug` that was wrong twice

This is about one bug found during the build (P5-5, D-057, D-061). It is a documentation bug, not a code bug: nothing leaked, and no behaviour changed. It was picked because it is the one nearest the project's central promise, that no secret reaches a message, a log or a panic. It shows how a security claim about a dependency can be written, "corrected" and still be wrong, with every step looking careful.

## What the claim was for

`docs/requirements.md` NFR-3 says no type that holds a secret implements `Debug` or `Display`. The reason is simple: a type with no `Debug` can't be formatted into an error message, a panic message or a log line by accident (`docs/design.md` §10). The secret types are built from `secrecy` and `zeroize` types, so the design had to say something about what those library types do.

## Timeline

1. **Phase 0.** `design.md` §10 said the library types (`SecretString`, `SecretBox<[u8]>`, `Zeroizing<[u8; 32]>`) don't implement `Debug` or `Display`, and that `static_assertions` would check this in tests. That was wrong: `secrecy`'s `SecretBox` implements `Debug` (it prints `[REDACTED]`), and so does `zeroize`'s `Zeroizing`. Nothing in the record shows that the crates' source was read.
2. **Phase 2, 2026-11-11** (commit `e5b609c`, D-039). The sentence was corrected. The new text said the library types do implement `Debug`, that `SecretBox` prints `[REDACTED]`, and that `Zeroizing<[u8; 32]>` "prints the raw bytes". The first half of that is right. The second half was not checked, and it is wrong. The record doesn't say how the first error was noticed.
3. **Phase 2, the code** (commit `cac9164`). The wrappers in `src/secret.rs` (`Key`, `Passphrase`, `SecretValue`, `SecretBytes`) hold the library types privately and implement neither trait. `tests/adversarial/secret_types.rs` asserts that, with `static_assertions`, for the wrappers and every type that holds one.
4. **Phase 5, 2026-11-14.** While this postmortem was being prepared, the pinned `zeroize` 1.9.1 was read for the first time. Its `Debug` for `Zeroizing<Z>` is `f.debug_struct("Zeroizing").finish_non_exhaustive()` (`zeroize-1.9.1/src/lib.rs:601`), which prints `Zeroizing { .. }` and no bytes. `Cargo.lock` has pinned 1.9.1 since commit `cac9164`, so no version change explains the Phase 2 sentence. It was never true for this project.

I read only the pinned 1.9.1. I don't know what older `zeroize` releases printed, and this document makes no claim about them.

## Impact

None on users. The rule the code enforces, "our types implement neither trait", never depended on what the library types print, so every wrapper was correct the whole time. The damage was in the docs: `design.md` §10, D-039 and a comment in `src/secret.rs` all stated something false about a dependency, and the reason given for a design choice was a reason that didn't exist. A reviewer who trusted that sentence would have believed in a danger that doesn't exist in this version.

## Why it happened

- **A claim about someone else's code was written from memory.** Both the original sentence and its correction describe what a crate does without a pointer to the crate's source or a test.
- **The correction was done carefully, and only half-checked.** It fixed the part that made the first sentence fail (`Debug` exists) and added a vivid detail (it prints the bytes) that fitted the story. Being right about one half made the other half feel checked.
- **The check that existed covered our types, not the claim.** The static assertions are about vaultline's types. Nothing exercised the sentence about the library's.

## What changed (D-061)

- `design.md` §10 and the comment in `src/secret.rs` now say what the pinned versions print, and that a later release could change it, which is why the library types stay inside the wrappers.
- `tests/adversarial/secret_types.rs` has a new test, `the_library_types_inside_the_wrappers_print_no_secret`. It formats a `SecretBox` and a `Zeroizing` that hold a known byte pattern, in both `{:?}` and `{:#?}`, and fails if the pattern shows. If a dependency update ever changes what they print, the test fails before the doc is wrong again.
- D-039 keeps its original text, with a pointer to the correction, so the history stays readable.

## What to do next time

1. A statement about what a dependency does gets a `file:line` in the pinned source, or a test, in the same change that writes it.
2. A correction is checked as hard as the claim it replaces, in both halves.
3. Keep the enforcement in vaultline's own types and tests, where a wrong belief about a library can't weaken it. That part worked.
