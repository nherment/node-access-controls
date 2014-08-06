build:
	node script/exportBrowserLibrary.js

test-browser:
	node_modules/.bin/mocha-phantomjs test/browser/test.html

test-node:
	node_modules/.bin/mocha test --reporter spec

test: build test-node test-browser
