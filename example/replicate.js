var trust = require('../');
var level = require('level')
var sodium = require('sodium')
var hsodium = require('hyperlog-sodium')

var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })
db.get('key', function (err, value) {
  var keypair = {
    secretKey: Buffer(value.secretKey, 'hex'),
    publicKey: Buffer(value.publicKey, 'hex')
  }
  var log = trust(db, hsodium(sodium, keypair, {
    publicKey: function (id, cb) { log.isTrusted(id, cb) }
  }))
  process.stdin.pipe(log.replicate()).pipe(process.stdout)
})
