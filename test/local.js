var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium')
if (sodium.api) sodium = sodium.api
var hsodium = require('hyperlog-sodium')
var eq = require('buffer-equals')
var hyperlog = require('hyperlog')
var through = require('through2')

test('local', function (t) {
  t.plan(4)
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
  var pending = 2
 
  var tlog0 = trust(memdb(), {
    verify: function (node, cb) {
      var m = sodium.crypto_sign_open(node.signature, node.identity)
      cb(null, eq(m, Buffer(node.key, 'hex')))
    }
  })
  tlog0.trust(kp1.publicKey, function (err) {
    t.ifError(err)
    if (--pending === 0) replicate()
  })
 
  var tlog1 = trust(memdb(), hsodium(sodium, kp1, {
    publicKey: function (id, cb) { tlog1.isTrusted(id, cb) }
  }))
  tlog1.trust(kp2.publicKey, function (err) {
    t.ifError(err)
    if (--pending === 0) replicate()
  })

  function replicate () {
    var r0 = tlog0.replicate()
    var r1 = tlog1.replicate()
    r0.once('finish', function () {
      tlog0.trusted(function (err, ids) {
        t.ifError(err)
        t.deepEqual(sort(ids), sort([
          kp1.publicKey, kp2.publicKey
        ]), 'picked up both keys on first use')
      })
    })
    r0.pipe(r1).pipe(r0)
  }
})

function sort (ids) {
  return ids.sort(cmp)
  function cmp (a, b) { return a.toString('hex') < b.toString('hex') ? -1 : 1 }
}
