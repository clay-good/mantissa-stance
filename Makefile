.PHONY: install test test-unit test-integration lint format typecheck clean help

# Default target
help:
	@echo "Mantissa Stance - Development Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install          Install package with dev dependencies"
	@echo "  test             Run all tests"
	@echo "  test-unit        Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  lint             Run linter (ruff)"
	@echo "  format           Format code (black)"
	@echo "  typecheck        Run type checker (mypy)"
	@echo "  clean            Remove build artifacts"
	@echo ""

# Install package in development mode
install:
	pip install -e ".[dev]"

# Run all tests
test:
	pytest tests/ -v --cov=src/stance --cov-report=term-missing

# Run unit tests only
test-unit:
	pytest tests/unit/ -v

# Run integration tests only
test-integration:
	pytest tests/integration/ -v

# Run linter
lint:
	ruff check src/ tests/

# Format code
format:
	black src/ tests/
	ruff check --fix src/ tests/

# Run type checker
typecheck:
	mypy src/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
