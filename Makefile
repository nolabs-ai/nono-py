.PHONY: build build-release dev install test lint lint-rust lint-python lint-ty \
        fmt fmt-rust fmt-python fmt-check fmt-check-rust fmt-check-python \
        typecheck security clean help release ci

# Pin cargo-driven steps to the venv interpreter so `make` works regardless
# of which Python is on the system PATH.
VENV_PYTHON := $(CURDIR)/.venv/bin/python
export PYO3_PYTHON ?= $(VENV_PYTHON)

# Default target
help:
	@echo "nono-py - Python bindings for nono sandboxing library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build        Build the package in debug mode"
	@echo "  build-release Build the package in release mode"
	@echo "  dev          Build and install in development mode"
	@echo "  install      Install the package"
	@echo ""
	@echo "Test targets:"
	@echo "  test         Run all tests"
	@echo "  test-quick   Run tests without rebuilding"
	@echo ""
	@echo "Quality targets:"
	@echo "  lint         Run all linters (clippy + ruff + mypy + ty)"
	@echo "  lint-rust    cargo clippy -D warnings"
	@echo "  lint-python  ruff check + mypy"
	@echo "  lint-ty      ty (Python type check)"
	@echo "  typecheck    Run mypy and ty together"
	@echo "  fmt          Format code (rustfmt + ruff)"
	@echo "  fmt-check    Check formatting (rustfmt + ruff, no changes)"
	@echo ""
	@echo "Release targets:"
	@echo "  release      Cut a release (make release VERSION=0.4.0)"
	@echo ""
	@echo "Other targets:"
	@echo "  clean        Remove build artifacts"

# Build in debug mode
build:
	uv run maturin build

# Build in release mode
build-release:
	uv run maturin build --release

# Development install (editable)
dev:
	uv run maturin develop

# Install the package
install:
	uv run maturin develop --release

# Run tests (rebuilds first)
test: dev
	uv run pytest tests/ -v

# Run tests without rebuilding
test-quick:
	uv run pytest tests/ -v

# Run Rust linter
lint-rust:
	cargo clippy -- -D warnings

# Run Python lint (ruff check) + type check (mypy)
lint-python:
	uv run ruff check python/ tests/
	uv run mypy python/nono_py

# Run ty over the project
lint-ty:
	uvx ty check python/

# Run mypy + ty together
typecheck:
	uv run mypy python/nono_py
	uvx ty check python/

# Run all linters
lint: lint-rust lint-python lint-ty

# Format Rust code
fmt-rust:
	cargo fmt

# Format Python code
fmt-python:
	-uv run ruff format python/ tests/
	-uv run ruff check --fix python/ tests/

# Format all code
fmt: fmt-rust fmt-python

# Check Rust formatting
fmt-check-rust:
	cargo fmt --check

# Check Python formatting
fmt-check-python:
	-uv run ruff format --check python/ tests/
	-uv run ruff check python/ tests/

# Check all formatting
fmt-check: fmt-check-rust fmt-check-python

# Security
security:
	uv export --no-hashes --frozen --no-editable | uvx pip-audit -r /dev/stdin
	cargo audit

# Remove build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.so" -delete 2>/dev/null || true

# CI target - run all checks
ci: fmt-check lint test security

# Release: make release VERSION=0.4.0
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=0.4.0)
endif
	@echo "Releasing v$(VERSION)..."
	sed -i '' 's/^version = ".*"/version = "$(VERSION)"/' pyproject.toml
	sed -i '' 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml
	git add pyproject.toml Cargo.toml
	git commit -m "Bump version to $(VERSION)"
	git tag v$(VERSION)
	git push origin main
	git push origin v$(VERSION)
	@echo "Released v$(VERSION) - publish workflow will handle PyPI"
