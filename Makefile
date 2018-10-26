all: docs

docs:
	npx jsdoc -r -c jsdoc.json -d doc --verbose --pedantic . README.md

lock:
	rm -r node_modules || true
	yarn install
	rm -r node_modules
	pnpm i

clean:
	rm -r doc
