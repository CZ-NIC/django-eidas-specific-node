.PHONY: test isort quality clean

APP = eidas_node
# Run `make test TESTS=...` to select tests to run. All tests are run by default.
TESTS ?=

test:
	tox --parallel all $(if $(TESTS),-- $(TESTS),)

isort:
	isort --recursive $(APP)

quality:
	tox -e quality

clean:
	find . -name __pycache__ -type d -exec rm -r {} +
	rm -rf build .coverage* dist htmlcov .mypy_cache .tox *.eggs *.egg-info
