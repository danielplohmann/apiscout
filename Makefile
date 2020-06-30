init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python3 setup.py sdist
publish:
	python3 -m twine upload dist/*
pylint:
	python3 -m pylint --rcfile=.pylintrc apiscout
test:
	python3 -m nose
test-coverage:
	python3 -m nose --with-coverage --cover-erase --cover-html-dir=./coverage-html --cover-html --cover-package=apiscout
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
