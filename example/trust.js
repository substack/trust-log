var trust = require('../');
var level = require('level')
var sub = require('subleveldown')
var sodium = require('sodium').api
var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })

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

  if (argv._[0] === 'trust') {
    var id = argv._[1]
    log.trust(id, function (err) {
      if (err) console.error(err)
    })
  } else if (argv._[0] === 'revoke') {
    var id = argv._[1]
    log.trust(id, function (err) {
      if (err) console.error(err)
    })
  } else if (argv._[0] === 'id') {
    console.log(keypair.publicKey.toString('hex'))
  } else if (argv._[0] === 'trusted') {
    log.trusted(function (err, ids) {
      ids.forEach(console.log.bind(console))
    })
  }
}

function toHex (keypair) {
  return {
    secretKey: keypair.secretKey.toString('hex'),
    publicKey: keypair.publicKey.toString('hex')
  }
}
