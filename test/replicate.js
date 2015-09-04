var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium')
if (sodium.api) sodium = sodium.api
var hsodium = require('hyperlog-sodium')
var eq = require('buffer-equals')
var hyperlog = require('hyperlog')
var through = require('through2')

test('replicate', function (t) {
  t.plan(5)
  var kp0 = sodium.crypto_sign_keypair()
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
 
  var tlog0 = trust(memdb(), hsodium(sodium, kp0, {
    publicKey: function (id, cb) { tlog0.isTrusted(id, cb) }
  }))
  var tlog1 = trust(memdb(), hsodium(sodium, kp1, {
    publicKey: function (id, cb) { tlog1.isTrusted(id, cb) }
  }))
  var tlog2 = trust(memdb(), hsodium(sodium, kp1, {
    publicKey: function (id, cb) { tlog2.isTrusted(id, cb) }
  }))
 
  var pending = 2
  tlog0.trust(kp1.publicKey, function (err) {
    t.ifError(err)
    if (--pending === 0) replicate()
  })
  tlog1.trust(kp0.publicKey, function (err) {
    t.ifError(err)
    tlog1.trust(kp2.publicKey, function (err) {
      t.ifError(err)
      if (--pending === 0) replicate()
    })
  })

  function replicate () {
    var r0 = tlog0.replicate({ live: false })
    var r1 = tlog1.replicate({ live: false })
    r0.once('finish', function () {
      tlog0.trusted(function (err, ids) {
        t.deepEqual(sort(ids), sort([
          kp0.publicKey, kp1.publicKey, kp2.publicKey
        ]), 'picked up key 3 from key 1')
      })
      tlog1.trusted(function (err, ids) {
        t.deepEqual(sort(ids), sort([
          kp0.publicKey, kp1.publicKey, kp2.publicKey
        ]), 'picked up key 3 from key 1')
      })
    })
    r0.pipe(r1).pipe(r0)
  }
})

function sort (ids) {
  return ids.sort(cmp)
  function cmp (a, b) { return a.toString('hex') < b.toString('hex') ? -1 : 1 }
}
