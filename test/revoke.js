var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium').api
var eq = require('buffer-equals')

test('revoke', function (t) {
  t.plan(10)
  var kp0 = sodium.crypto_sign_keypair()
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
 
  var log = trust(memdb(), {
    id: kp0.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, kp0.secretKey))
    },
    verify: function (node, publicKey, cb) {
      var bkey = Buffer(node.key, 'hex')
      var m = sodium.crypto_sign_open(node.signature, node.identity)
      cb(null, eq(m, publicKey))
    }
  })
 
  log.trusted(function (err, ids) {
    t.ifError(err)
    t.deepEqual(ids, [ kp0.publicKey ])
  })
  log.trust(kp1.publicKey, function (err) {
    t.ifError(err)
    log.trusted(function (err, ids) {
      t.ifError(err)
      t.deepEqual(sort(ids), sort([ kp0.publicKey, kp1.publicKey ]))
      log.trust(kp2.publicKey, function (err) {
        log.trusted(function (err, ids) {
          t.ifError(err)
          t.deepEqual(
            sort(ids),
            sort([ kp0.publicKey, kp1.publicKey, kp2.publicKey ])
          )
          revoke()
        })
      })
    })
  })
 
  function revoke () {
    log.revoke(kp1.publicKey, function (err) {
      t.ifError(err)
      log.trusted(function (err, ids) {
        t.ifError(err)
        t.deepEqual(
          sort(ids),
          sort([ kp0.publicKey, kp2.publicKey ])
        )
      })
    })
  }
})

function sort (ids) {
  return ids.sort(cmp)
  function cmp (a, b) { return a.toString('hex') < b.toString('hex') ? -1 : 1 }
}
