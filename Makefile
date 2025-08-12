.PHONY: fmt
fmt:
	cargo fmt


.PHONY: check
check:
	RUSTFLAGS="-C target-feature=-avx2,-simd128" cargo check 2>/dev/null
	cargo check

# check for all supported targets and target features
.PHONY: check_all
check_all:
	RUSTFLAGS="-C target-feature=-avx2" cargo check --target=x86_64-unknown-linux-gnu
	RUSTFLAGS="-C target-feature=+avx2" cargo check --target=x86_64-unknown-linux-gnu

# aarch64 assumes that NEON is always present
	RUSTFLAGS="-C target-feature=+neon" cargo check --target=aarch64-unknown-linux-gnu

	RUSTFLAGS="-C target-feature=-simd128" cargo check --target=wasm32-unknown-unknown
	RUSTFLAGS="-C target-feature=+simd128" cargo check --target=wasm32-unknown-unknown


.PHONY: test
test:
	RUST_BACKTRACE=1 cargo test


.PHONY: bench
bench:
	RUSTFLAGS="-C target-cpu=native --cfg chacha20_force_avx2" cargo bench
# -C target-feature=+aes,+avx512f,+ssse3,+vaes
# --cfg aes_avx256 or --cfg aes_avx512

.PHONY: release
release: mdninja
	date
	git checkout main
	git push
	git checkout release
	git merge main
	git push
	git checkout main
