all: docs

docs:
	jsdoc -r -c jsdoc.json -d doc --verbose --pedantic .

clean:
	rm -r doc
