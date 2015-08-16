var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium').api
var eq = require('buffer-equals')
var hyperlog = require('hyperlog')
var through = require('through2')

test('verify', function (t) {
  t.plan(6)
  var kp0 = sodium.crypto_sign_keypair()
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
  var expectedVerify = [ true ]
  var keys = [ kp1, kp2 ]
  var expectedKeys = keys.slice()
 
  var tlog = trust(memdb(), {
    id: kp0.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, kp0.secretKey))
    }
  })
  var hlog = hyperlog(memdb(), {
    valueEncoding: 'json',
    identity: kp1.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, keys.shift().secretKey))
    },
    verify: function (node, cb) {
      tlog.verify(node, cb)
    }
  })
  hlog.add(null, 'beep', function (err, node) {
    t.ifError(err)
    hlog.add([node.key], 'boop', function (err, node) {
      t.ifError(err)
    })
  })
 
  tlog.trust(kp1.publicKey, verify)
  function verify (err) {
    t.ifError(err)
    hlog.createReadStream().pipe(through.obj(write))
    function write (row, enc, next) {
      tlog.verify(row, function (err, ok) {
        t.ifError(err)
        t.equal(ok, expectedVerify.shift(), 'verify')
        t.deepEqual(
          row.identity,
          expectedKeys.shift().publicKey,
          'expected key'
        )
      })
      next()
    }
  }
})

function sort (ids) {
  return ids.sort(cmp)
  function cmp (a, b) { return a.toString('hex') < b.toString('hex') ? -1 : 1 }
}
