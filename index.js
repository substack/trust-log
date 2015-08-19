var hyperlog = require('hyperlog')
var hindex = require('hyperlog-index')
var sub = require('subleveldown')
var eq = require('buffer-equals')
var through = require('through2')
var readonly = require('read-only-stream')
var collect = require('collect-stream')
var once = require('once')
var isarray = require('isarray')
var defined = require('defined')
var concat = require('concat-map')

module.exports = TrustLog

function TrustLog (db, opts) {
  if (!(this instanceof TrustLog)) return new TrustLog(db, opts)
  var self = this
  if (!opts) opts = {}
  this.log = hyperlog(sub(db, 'l'), {
    valueEncoding: 'json',
    identity: defined(opts.identity, opts.id, null),
    sign: function (node, cb) {
      if (opts.sign) opts.sign(node, cb)
      else cb(new Error('cannot sign messages when opts.sign not provided'))
    },
    verify: function (node, cb) {
      self.verify(node, cb)
    }
  })
  this._verify = opts.verify
  this._id = defined(opts.identity, opts.id, null)
  if (typeof this._id === 'string') this._id = Buffer(opts.id, 'hex')
  this.dex = hindex(
    this.log,
    sub(db, 'i', { valueEncoding: 'json' }),
    indexer
  )

  function indexer (row, tx, next) {
    if (row.value && row.value.op === 'trust') {
      tx.get('revoke!' + row.value.id, function (err, value) {
        if (notFound(err)) {
          tx.put('trust!' + row.value.id, {}, next)
        }
        else if (err) next(err)
        else next(new Error('cannot re-trust a previously revoked key'))
      })
    }
    else if (row.value && row.value.op === 'revoke') {
      var value = {
        time: row.value.time,
        by: row.signature.toString('hex'),
        external: row.value.external || []
      }
      tx.batch([
        { type: 'put', key: 'revoke!' + row.value.id, value: value },
        { type: 'del', key: 'trust!' + row.value.id }
      ], next)
    }
    else {
      // ignore unknown op types
      next()
    }
  }
}

TrustLog.prototype.trust = function (node, cb) {
  var self = this
  if (typeof node === 'string') {
    node = { id: node }
  } else if (Buffer.isBuffer(node)) {
    node = { id: node.toString('hex') }
  }
  if (!cb) cb = noop
  var value = {
    op: 'trust',
    id: node.id,
    time: defined(node.time, Date.now())
  }

  // todo: check here to see if the key has been revoked previously
  if (node.links === undefined) {
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else self.log.add(heads.map(keyof), value, cb)
      })
    })
  } else self.log.add(node.links, value, cb)
}

TrustLog.prototype.revoke = function (node, cb) {
  var self = this
  if (typeof node === 'string') {
    node = { id: node }
  } else if (Buffer.isBuffer(node)) {
    node = { id: node.toString('hex') }
  }
  if (!cb) cb = noop
 
  var value = {
    op: 'revoke',
    id: node.id,
    time: defined(node.time, Date.now())
  }

  if (node.links === undefined) {
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else self.log.add(heads.map(keyof), value, cb)
      })
    })
  } else self.log.add(node.links, value, cb)
}

TrustLog.prototype.trusted = function (from, cb) {
  var self = this
  if (typeof from === 'function') {
    cb = from
    from = null
  }
  if (!cb) cb = noop
  else cb = once(cb)
 
  var output = through.obj()
  if (self._id !== undefined) output.push({ id: self._id })
 
  if (!from || (isarray(from) && from.length === 0)) {
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else onready(heads)
      })
    })
  } else load(from)
 
  function load (from) {
    if (!isarray(from)) from = [from]
    self.dex.ready(function () { onready(from) })
  }
  function onready (heads) {
    var pending = 1
    heads.forEach(function (head) {
      var key = typeof head === 'string' ? head : head.key
      pending ++
      var tx = self.dex.open(key)
      var r = tx.createReadStream({ gt: 'trust!', lt: 'trust!~' })
      var tr = r.pipe(through.obj(function (row, enc, next) {
        this.push({
          id: Buffer(row.key.split('!')[1], 'hex')
        })
        next()
      }))
      tr.pipe(output, { end: false })
      tr.once('end', done)
      tr.once('end', function () { tx.close() })
    })
    done()
    function done () {
      if (--pending === 0) output.push(null)
    }
  }
  if (cb) collect(output, function (err, ids) {
    if (ids) cb(null, ids.map(function (i) { return i.id }))
  })
  return readonly(output)
}

TrustLog.prototype.isTrusted = function (from, pubkey, cb) {
  var self = this
  if (typeof pubkey === 'function') {
    cb = pubkey
    pubkey = from
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        self.trusted(links(heads), ontrusted)
      })
    })
  } else self.trusted(from, ontrusted)

  function ontrusted (err, ids) {
    if (err) return cb(err)
    for (var i = 0; i < ids.length; i++) {
      if (eq(ids[i], pubkey)) return cb(null, true)
    }
    cb(null, false)
  }
}

TrustLog.prototype.verify = function (node, cb) {
  var self = this
  if (!self._verify) {
    var err = new Error('no verification function provided')
    return process.nextTick(function () { cb(err) })
  }
  if (node.links.length === 0) {
    //self.dex.ready(function () {
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else onready(heads)
      })
    })
  } else self.dex.ready(node.links, function () { onready() })

  function onready () {
    if (!node.signature) return cb(null, false)
    self.trusted(node.links, function (err, ids) {
      if (err) return cb(err)
      var id = null
      for (var i = 0; i < ids.length; i++) {
        if (eq(ids[i], node.identity)) {
          id = ids[i]
          break
        }
      }
      if (!id) return cb(null, false)
      var bkey = Buffer(node.key, 'hex')
      self._verify(node, cb)
    })
  }
}

TrustLog.prototype.replicate = function () {
  return this.log.replicate()
}

function notFound (err) {
  return err && (/notfound/i.test(err) || err.notFound)
}

function keyof (node) { return node.key }
function noop () {}

function links (nodes) {
  return concat(nodes, function (node) { return node.links || [] })
}
