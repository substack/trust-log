var trust = require('../');
var level = require('level')
var sub = require('subleveldown')
var sodium = require('sodium').api
var minimist = require('minimist')
var concat = require('concat-stream')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })
db.get('key', function (err, value) {
  if (err) return console.error(err)
  console.log(value.publicKey)
})
