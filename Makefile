all: docs

docs:
	jsdoc -r -c jsdoc.json -d doc --verbose --pedantic .
