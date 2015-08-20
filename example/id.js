var trust = require('../');
var level = require('level')
var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })
db.get('key', function (err, value) {
  if (err) return console.error(err)
  console.log(value.publicKey)
})
