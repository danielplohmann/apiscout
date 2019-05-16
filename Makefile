init:
	pip install -r requirements.txt

test:
	nosetests tests
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
