var trust = require('../');
var level = require('level')
var sub = require('subleveldown')
var sodium = require('sodium').api

var db = level('/tmp/trust.db', { valueEncoding: 'json' })

db.get('key', function (err, keypair) {
  if (keypair) return ready(keypair)
  keypair = toHex(sodium.crypto_sign_keypair())
  db.put('key', keypair, function (err) {
    if (err) console.error(err)
    else ready(keypair)
  })
})

function ready (keypair) {
  var log = trust(sub(db, 'trust'), keypair)

  if (process.argv[2] === 'trust') {
    var id = process.argv[3]
    log.trust(id, function (err) {
      if (err) console.error(err)
    })
  }
  else if (process.argv[2] === 'revoke') {
    var id = process.argv[3]
    log.trust(id, function (err) {
      if (err) console.error(err)
    })
  }
  else if (process.argv[2] === 'id') {
    console.log(keypair.publicKey.toString('hex'))
  }
}

function toHex (keypair) {
  return {
    secretKey: keypair.secretKey.toString('hex'),
    publicKey: keypair.publicKey.toString('hex')
  }
}
