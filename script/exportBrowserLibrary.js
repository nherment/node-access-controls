
var fs = require('fs')
var path = require('path')
var browserify = require('browserify')

var packageJsonData = require(__dirname + '/../package.json')

var exportedBrowserLibraryPath = path.normalize(__dirname + '/../dist/'+packageJsonData.name + '-'+packageJsonData.version + '.js')

var b = browserify()

b.add('./index.js')
b.bundle().pipe(fs.createWriteStream(exportedBrowserLibraryPath))

console.log('browser compatible library ==>', exportedBrowserLibraryPath)
