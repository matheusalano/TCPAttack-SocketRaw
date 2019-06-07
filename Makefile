.PHONY: tests run run-server run-client



tests:
	nosetests tests

run:
	python3 runner.py $(type)

run-attack:
	python3 runner.py 0

run-defense:
	python3 runner.py 1