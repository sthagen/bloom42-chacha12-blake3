.PHONY: fmt
fmt:
	cargo fmt


.PHONY: test
test:
	cargo test


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
