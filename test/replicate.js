var test = require('tape')
var trust = require('../');
var memdb = require('memdb')
var sodium = require('sodium').api
var hsodium = require('hyperlog-sodium')
var eq = require('buffer-equals')
var hyperlog = require('hyperlog')
var through = require('through2')

test('replicate', function (t) {
  t.plan(7)
  var kp0 = sodium.crypto_sign_keypair()
  var kp1 = sodium.crypto_sign_keypair()
  var kp2 = sodium.crypto_sign_keypair()
  var kp3 = sodium.crypto_sign_keypair()
 
  var expectedVerify = [ true ]
  var keys = [ kp1, kp2 ]
  var expectedKeys = keys.slice()

  var tlog0 = trust(memdb(), hsodium(sodium, kp0, {
    publicKey: function (id, cb) { tlog0.isTrusted(id, cb) }
  }))
  var tlog1 = trust(memdb(), hsodium(sodium, kp1, {
    publicKey: function (id, cb) { tlog1.isTrusted(id, cb) }
  }))
  var tlog2 = trust(memdb(), hsodium(sodium, kp2, {
    publicKey: function (id, cb) { tlog2.isTrusted(id, cb) }
  }))
  var tlog3 = trust(memdb(), hsodium(sodium, kp3, {
    publicKey: function (id, cb) { tlog3.isTrusted(id, cb) }
  }))
 
  tlog0.trust(kp1.publicKey, function (err) {
    t.ifError(err)
    tlog1.trust(kp3.publicKey, function (err) {
      t.ifError(err)
      tlog2.revoke(kp1.publicKey, function (err) {
        t.ifError(err)
        replicate01()
      })
    })
  })

  function replicate01 () {
    var r0 = tlog0.replicate({ live: false })
    var r1 = tlog1.replicate({ live: false })
    r0.once('finish', function () {
      tlog0.trusted(function (err, ids) {
        t.deepEqual(sort(ids), sort([
          kp0.publicKey, kp1.publicKey, kp3.publicKey
        ]), 'picked up key 3 from key 1')
        replicate02()
      })
    })
    r0.pipe(r1).pipe(r0)
  }

  function replicate02 () {
    var r0 = tlog0.replicate({ live: false })
    var r3 = tlog3.replicate({ live: false })
    r0.pipe(r3).pipe(r0)
    r0.on('error', function (err) {
      t.ok(err, 'replication with 2 rejected')
      tlog0.trusted(function (err, ids) {
        t.ifError(err)
        t.deepEqual(sort(ids), sort([
          kp0.publicKey, kp1.publicKey, kp3.publicKey
        ]), 'key rejection rejected')
      })
    })
  }
})

function sort (ids) {
  return ids.sort(cmp)
  function cmp (a, b) { return a.toString('hex') < b.toString('hex') ? -1 : 1 }
}
