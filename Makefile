.PHONY: fmt
fmt:
	cargo fmt


.PHONY: check
check:
	RUSTFLAGS="-C target-feature=-avx2,-simd128,-avx512f" cargo check
	cargo check

# check for all supported targets and target features
.PHONY: check_all
check_all:
	RUSTFLAGS="-C target-feature=-avx2,-avx512f" cargo check --target=x86_64-unknown-linux-gnu
	RUSTFLAGS="-C target-feature=+avx2,+avx512f" cargo check --target=x86_64-unknown-linux-gnu

	cargo check --target=aarch64-unknown-linux-gnu

	RUSTFLAGS="-C target-feature=-simd128" cargo check --target=wasm32-wasip1
	RUSTFLAGS="-C target-feature=+simd128" cargo check --target=wasm32-wasip1


.PHONY: test
test:
	RUST_BACKTRACE=1 cargo test


.PHONY: test_wasm
test_wasm:
	WASMTIME_BACKTRACE_DETAILS=1 RUST_BACKTRACE=1 RUSTFLAGS="-C target-feature=-simd128" cargo test -p chacha12 --target=wasm32-wasip1 -- --nocapture
	WASMTIME_BACKTRACE_DETAILS=1 RUST_BACKTRACE=1 RUSTFLAGS="-C target-feature=+simd128" cargo test -p chacha12 --target=wasm32-wasip1 -- --nocapture


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
