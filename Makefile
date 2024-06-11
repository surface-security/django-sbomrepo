.PHONY: lint
lint:
	black .
	ruff --fix .

.PHONY: test
test:
	testapp/manage.py test $${TEST_ARGS:-tests}

.PHONY: coverage
coverage:
	PYTHONPATH="testapp" \
		python -b -W always -m coverage run testapp/manage.py test $${TEST_ARGS:-tests}
	coverage report