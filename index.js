var hyperlog = require('hyperlog')
var hindex = require('hyperlog-index')
var sub = require('subleveldown')
var eq = require('buffer-equals')
var through = require('through2')
var readonly = require('read-only-stream')
var collect = require('collect-stream')
var once = require('once')
var has = require('has')
var isarray = require('isarray')
var defined = require('defined')
var concat = require('concat-map')
var duplexify = require('duplexify')

module.exports = TrustLog

function TrustLog (db, opts) {
  if (!(this instanceof TrustLog)) return new TrustLog(db, opts)
  var self = this
  if (!opts) opts = {}
  this._tofu = opts.tofu
  this._id = defined(opts.identity, opts.id, null)
  this._local = sub(db, 'z')
  this.log = hyperlog(sub(db, 'l'), {
    valueEncoding: 'json',
    identity: this._id,
    sign: function (node, cb) {
      if (opts.sign) opts.sign(node, cb)
      else cb(new Error('cannot sign messages when opts.sign not provided'))
    },
    verify: function (node, cb) {
      if (self._tofu) {
        count(self.log.createReadStream({ limit: 1 }), function (err, n) {
          if (n > 0) self._tofu = false
          if (err) cb(err)
          else if (n === 0) cb(null, true)
          else self._verifyNow(node.links, node, cb)
        })
      } else self._verifyNow(node.links, node, cb)
    }
  })
  this._verify = opts.verify
  if (typeof this._id === 'string') this._id = Buffer(opts.id, 'hex')
  this.dex = hindex(
    this.log,
    sub(db, 'i', { valueEncoding: 'json' }),
    indexer
  )
  if (this._id && opts.sign) this.trust(this._id)

  function indexer (row, tx, next) {
    if (row.value && row.value.op === 'trust') {
      tx.get('revoke!' + row.value.id, function (err, value) {
        if (notFound(err)) {
          tx.get('trust!' + row.value.id, function (err) {
            if (notFound(err)) tx.put('trust!' + row.value.id, {}, next)
            else if (err) next(err)
            else next()
          })
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
  if (!self._id) {
    return self._local.put(node.id, '0', cb)
  }
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
  if (!self._id) {
    return self._local.del(node.id, '0', cb)
  }
 
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
  if (from && !isarray(from)) from = [from]
 
  var dup = duplexify.obj()
  if (!from) {
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else load(heads.map(keyof))
      })
    })
  } else load(from)

  function load (from) {
    if (from.length) self.dex.ready(from, onready)
    else onready()

    function onready () {
      dup.setReadable(self._trustedNow(from, cb))
    }
  }
  return readonly(dup)
}

TrustLog.prototype._trustedNow = function (heads, cb) {
  var self = this
  var output = through.obj()
  if (self._id) output.push({ id: self._id })
 
  if (!heads) heads = []
  var seen = {}
  if (self._id) seen[self._id.toString('hex')] = true
 
  if (!isarray(heads)) heads = [heads]
  var pending = 2
  self._local.createReadStream()
    .pipe(through.obj(function (row, enc, next) {
      seen[row.key] = true
      output.push({ id: Buffer(row.key, 'hex') })
      next()
    }, done))

  heads.forEach(function (head) {
    pending ++
    var tx = self.dex.open(head)
    var r = tx.createReadStream({ gt: 'trust!', lt: 'trust!~' })
    var tr = r.pipe(through.obj(function (row, enc, next) {
      var hexid = row.key.split('!')[1]
      if (!has(seen, hexid)) {
        this.push({ id: Buffer(hexid, 'hex') })
        seen[hexid] = true
      }
      next()
    }))
    tr.pipe(through.obj(function (row, enc, next) {
      if (self._id && eq(row.id, self._id)) {}
      else this.push(row)
      next()
    })).pipe(output, { end: false })
    tr.once('end', done)
    tr.once('end', function () { tx.close() })
  })
  done()
  function done () {
    if (--pending === 0) output.push(null)
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
    from = null
  }
  if (self._id && eq(pubkey, self._id)) return nextTick(cb, null, true)
  else self.trusted(from, ontrusted)

  function ontrusted (err, ids) {
    if (err) return cb(err)
    for (var i = 0; i < ids.length; i++) {
      if (eq(ids[i], pubkey)) return cb(null, true)
    }
    cb(null, false)
  }
}

TrustLog.prototype._isTrustedNow = function (from, pubkey, cb) {
  var self = this
  if (self._id && eq(pubkey, self._id)) return nextTick(cb, null, true)
  self.trusted(function (err, ids) {
    if (err) return cb(err)
    for (var i = 0; i < ids.length; i++) {
      if (eq(ids[i], pubkey)) return cb(null, true)
    }
    cb(null, false)
  })
}

TrustLog.prototype.verify = function (from, node, cb) {
  var self = this
  if (!self._verify) {
    return nextTick(cb, new Error('no verification function provided'))
  }
  if (!node || typeof node === 'function') {
    cb = node
    node = from
    from = null
  }
  if (!cb) cb = noop
  if (!node.signature) return nextTick(cb, null, false)
  if (!node.identity) return nextTick(cb, null, false)

  self.isTrusted(from, node.identity, function (err, ok) {
    if (err) cb(err)
    else if (!ok) cb(null, false)
    else self._verify(node, cb)
  })
}

TrustLog.prototype._verifyNow = function (from, node, cb) {
  var self = this
  if (!self._verify) {
    return nextTick(cb, new Error('no verification function provided'))
  }
  if (!cb) cb = noop
  if (!node.signature) return nextTick(cb, null, false)
  if (!node.identity) return nextTick(cb, null, false)
  self._isTrustedNow(from, node.identity, function (err, ok) {
    if (err) cb(err)
    else if (!ok) cb(null, false)
    else self._verify(node, cb)
  })
}

TrustLog.prototype.replicate = function (opts) {
  var self = this
  var dup = duplexify()
  self.dex.ready(function () {
    var r = self.log.replicate(opts)
    dup.setReadable(r)
    dup.setWritable(r)
    r.on('finish', function () { dup.emit('finish') })
  })
  return dup
}

function notFound (err) {
  return err && (/notfound/i.test(err) || err.notFound)
}

function keyof (node) { return node.key }
function noop () {}
function nextTick (cb) {
  var args = [].slice.call(arguments, 1)
  process.nextTick(function () { cb.apply(null, args) })
}

function count (stream, cb) {
  cb = once(cb)
  var count = 0
  stream.once('error', cb)
  stream.pipe(through.obj(write, end))
  function write (row, enc, next) { count ++; next() }
  function end () { cb(null, count) }
}
