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

module.exports = TrustLog

function TrustLog (db, opts) {
  if (!(this instanceof TrustLog)) return new TrustLog(db, opts)
  if (!opts) opts = {}
  this.log = hyperlog(sub(db, 'l'), {
    valueEncoding: 'json',
    identity: defined(opts.identity, null),
    sign: function (node, cb) {
      if (opts.sign) opts.sign(node, cb)
      else cb(new Error('cannot sign messages when opts.sign not provided'))
    },
    verify: function (node, cb) {
      // check updates against known current HEADs
    }
  })
  this._verify = opts.verify
  this._id = typeof opts.id === 'string' ? Buffer(opts.id, 'hex') : opts.id
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

TrustLog.prototype.trust = function (id, opts, cb) {
  var self = this
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!opts) opts = {}
  if (!cb) cb = noop
  var value = {
    op: 'trust',
    id: typeof id === 'string' ? id : id.toString('hex')
  }
  if (opts.external) value.external = [].concat(opts.external)
  if (opts.time) value.time = opts.time && typeof opts.time === 'object'
    ? opts.time.getTime() : opts.time
  else if (opts.time !== false) value.time = Date.now()

  // todo: check here to see if the key has been revoked previously
  self.log.ready(function () {
    self.log.heads(function (err, heads) {
      if (err) return cb(err)
      self.log.add(heads.map(keyof), value, cb)
    })
  })
}

TrustLog.prototype.revoke = function (id, opts, cb) {
  var self = this
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!opts) opts = {}
  if (!cb) cb = noop
 
  var value = {
    op: 'revoke',
    id: typeof id === 'string' ? id : id.toString('hex')
  }
  if (opts.external) value.external = [].concat(opts.external)
  if (opts.time) value.time = opts.time && typeof opts.time === 'object'
    ? opts.time.getTime() : opts.time
  else if (opts.time !== false) value.time = Date.now()

  self.log.ready(function () {
    self.log.heads(function (err, heads) {
      if (err) return cb(err)
      self.log.add(heads.map(keyof), value, cb)
    })
  })
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
        else load(heads)
      })
    })
  } else load(from)
 
  function load (from) {
    if (!isarray(from)) from = [from]
    self.log.ready(function () { onready(from) })
  }
  function onready (heads) {
    var pending = 1
    heads.forEach(function (head) {
      pending ++
      var tx = self.dex.open(head.key)
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

TrustLog.prototype.verify = function (from, node, cb) {
  var self = this
  if (!self._verify) {
    var err = new Error('no verification function provided')
    return process.nextTick(function () { cb(err) })
  }
  if (typeof node === 'function' || !from || from.length === 0) {
    cb = node
    node = from
    self.log.ready(function () {
      self.log.heads(function (err, heads) {
        if (err) cb(err)
        else onready(heads)
      })
    })
  }
  else self.log.ready(function () { onready(from) })

  function onready (heads) {
    if (!isarray(heads)) heads = [heads]
    if (!node.signature) return cb(null, false)
    self.trusted(heads, function (err, ids) {
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

function notFound (err) {
  return err && (/notfound/i.test(err) || err.notFound)
}

function keyof (node) { return node.key }
function noop () {}
