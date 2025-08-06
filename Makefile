.PHONY: fmt
fmt:
	cargo fmt


.PHONY: test
test:
	cargo test


.PHONY: bench
bench:
	RUSTFLAGS="-C target-cpu=native --cfg chacha20_force_avx2" cargo bench


.PHONY: release
release: mdninja
	date
	git checkout main
	git push
	git checkout release
	git merge main
	git push
	git checkout main
