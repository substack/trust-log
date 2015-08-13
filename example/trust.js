var trust = require('../');
var level = require('level')
var sub = require('subleveldown')
var sodium = require('sodium').api
var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })

db.get('key', function (err, keypair) {
  if (keypair) return ready(fromHex(keypair))
  keypair = toHex(sodium.crypto_sign_keypair())
  db.put('key', keypair, function (err) {
    if (err) console.error(err)
    else ready(fromHex(keypair))
  })
})

function ready (keypair) {
  var log = trust(sub(db, 'trust'), {
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, keypair.secretKey))
    },
    verify: function (node, publicKey, cb) {
      var bkey = Buffer(node.key, 'hex')
      var m = sodium.crypto_sign_open(node.signature, node.identity)
      return m
    }
  })

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
      ids.forEach(function (id) {
        console.log(id.id)
      })
    })
  }
}

function toHex (keypair) {
  return {
    secretKey: keypair.secretKey.toString('hex'),
    publicKey: keypair.publicKey.toString('hex')
  }
}

function fromHex (keypair) {
  return {
    secretKey: Buffer(keypair.secretKey, 'hex'),
    publicKey: Buffer(keypair.publicKey, 'hex')
  }
}
