# vaultline: local and CI entry points. See docs/phases.md (Phase 1) and D-022.
#
# `audit` and `fuzz` need tools that are not installed on the developer Mac
# (cargo-deny, cargo-audit, cargo-fuzz and the nightly toolchain). When a tool
# is missing they print SKIPPED and succeed, unless CI=true, where a missing
# tool is an error. Nothing here installs anything.

FUZZ_SECONDS ?= 60

.PHONY: test lint audit fuzz bench

test:
	cargo test --locked

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

# $(call run_or_skip,<tool>,<command>): run <command> if <tool> is on the PATH.
define run_or_skip
@if command -v $(1) >/dev/null 2>&1; then \
	$(2); \
elif [ "$$CI" = "true" ]; then \
	echo "error: $(1) is not installed" >&2; exit 1; \
else \
	echo "SKIPPED: $(1) not installed; this check runs in CI"; \
fi
endef

audit:
	$(call run_or_skip,cargo-deny,cargo deny check)
	$(call run_or_skip,cargo-audit,cargo audit)

# Smoke run: FUZZ_SECONDS (default 60) per fuzz target. The long campaign runs
# only in the fuzz-campaign GitHub Actions workflow. The nightly toolchain is
# looked up with `rustup toolchain list`, never invoked as `cargo +nightly`
# first, so that a missing toolchain is never downloaded.
fuzz:
	@missing=""; \
	command -v cargo-fuzz >/dev/null 2>&1 || missing="cargo-fuzz"; \
	if [ -z "$$missing" ]; then \
		if ! command -v rustup >/dev/null 2>&1 || ! rustup toolchain list | grep -q '^nightly'; then \
			missing="the nightly toolchain"; \
		fi; \
	fi; \
	if [ -n "$$missing" ]; then \
		if [ "$$CI" = "true" ]; then echo "error: $$missing is not installed" >&2; exit 1; fi; \
		echo "SKIPPED: $$missing not installed; this check runs in CI"; \
		exit 0; \
	fi; \
	for target in $$(cargo +nightly fuzz list); do \
		echo "fuzzing $$target for $(FUZZ_SECONDS)s"; \
		cargo +nightly fuzz run $$target -- -max_total_time=$(FUZZ_SECONDS) || exit 1; \
	done

# Benchmarks arrive in Phase 2 (unlock) and Phase 5 (run overhead).
bench:
	@echo "no benchmarks yet; the unlock benchmark arrives in Phase 2"
