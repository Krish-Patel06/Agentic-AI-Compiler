.PHONY: all demo test server clean

PYTHON ?= python

all: test

demo:
	$(PYTHON) run_demo.py

test:
	$(PYTHON) -m unittest discover -s tests -p "test_phase*.py"

server:
	$(PYTHON) -m api.server 8000

clean:
	@echo "Cleaning cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf compiler_artifacts/ build/ 2>/dev/null || true
