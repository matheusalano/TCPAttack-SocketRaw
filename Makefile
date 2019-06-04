.PHONY: tests run run-server run-client



tests:
	nosetests tests

run:
	python3 runner.py $(type)

run-server:
	python3 runner.py 0

run-client:
	python3 runner.py 1