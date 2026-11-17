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
	python3 -m unittest discover -s tests -p "test*.py" -t .
test-coverage:
	python3 -m coverage erase
	python3 -m coverage run -m unittest discover -s tests -p "test*.py" -t .
	python3 -m coverage html -d ./coverage-html
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
