.PHONY: build check clean fmt lint test
build:
	cargo build
check:
	cargo check
clean:
	rm -rf target
fmt:
	cargo fmt
lint:
	cargo clippy
test: build
	deno test --allow-all --quiet .
