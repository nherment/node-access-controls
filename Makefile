build:
	node script/exportBrowserLibrary.js

test-browser:
	mocha-phantomjs test/browser/test.html

test-node:
	mocha test --reporter spec

test: build test-node test-browser
