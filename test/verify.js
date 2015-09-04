var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium')
if (sodium.api) sodium = sodium.api
var eq = require('buffer-equals')
var hyperlog = require('hyperlog')
var through = require('through2')

test('verify', function (t) {
  t.plan(9)
  var kp0 = sodium.crypto_sign_keypair()
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
  var keys = [ kp1, kp2 ]
  var expectedKeys = keys.concat(kp0)
 
  var tlog = trust(memdb(), {
    identity: kp0.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, kp0.secretKey))
    },
    verify: function (node, cb) {
      var m = sodium.crypto_sign_open(node.signature, node.identity)
      cb(null, m && eq(m, Buffer(node.key, 'hex')))
    }
  })
  var hlog0 = hyperlog(memdb(), {
    valueEncoding: 'json',
    identity: kp1.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, kp1.secretKey))
    },
    verify: function (node, cb) { cb(null, true) }
  })
  var hlog1 = hyperlog(memdb(), {
    valueEncoding: 'json',
    identity: kp2.publicKey,
    sign: function (node, cb) {
      var bkey = Buffer(node.key, 'hex')
      cb(null, sodium.crypto_sign(bkey, kp2.secretKey))
    },
    verify: function (node, cb) { cb(null, true) }
  })

  hlog0.add(null, 'beep', function (err, node) {
    t.ifError(err)
    var r0 = hlog0.replicate()
    var r1 = hlog1.replicate()
    r0.pipe(r1).pipe(r0)
    r0.once('finish', function () {
      hlog1.add([node.key], 'boop', function (err, node) {
        t.ifError(err)
        var pending = 2
        tlog.trust(kp1.publicKey, done)
        tlog.trust(kp2.publicKey, done)
        function done () { if (--pending === 0) verify() }
      })
    })
  })
 
  function verify (err) {
    t.ifError(err)
    hlog1.createReadStream().pipe(through.obj(write))
    function write (row, enc, next) {
      tlog.verify(row, function (err, ok) {
        t.ifError(err)
        t.equal(ok, true)
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
