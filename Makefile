demo:
	python3 demo.py
test:
	python3 -m unittest discover -s tests -t . -v
claims:
	python3 claims_check.py
mutations:
	python3 claims_check.py --mutations
serve:
	python3 -m app.server --port 8000
