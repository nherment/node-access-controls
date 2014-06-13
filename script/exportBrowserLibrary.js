
var fs = require('fs')
var path = require('path')
var browserify = require('browserify')

var packageJsonData = require(__dirname + '/../package.json')

var exportedBrowserLibraryPath = __dirname + '/../dist/'+packageJsonData.name + '.js'

var b = browserify()

b.add('./index.js')
b.bundle({
  standalone: 'AccessControls'
}).pipe(fs.createWriteStream(exportedBrowserLibraryPath))

console.log('browser compatible library ==>', exportedBrowserLibraryPath)
