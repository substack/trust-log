var trust = require('../');
var level = require('level')
var sub = require('subleveldown')
var sodium = require('sodium').api
var minimist = require('minimist')
var concat = require('concat-stream')
var argv = minimist(process.argv.slice(2))

var keypair = sodium.crypto_sign_keypair()
var value = {
  secretKey: keypair.secretKey.toString('hex'),
  publicKey: keypair.publicKey.toString('hex')
}

var db = level(argv.d, { valueEncoding: 'json' })
db.put('key', keypair, function (err) {
  if (err) console.error(err)
})
