# trust-log

add and revoke trust over time

Stores trust events in a log so that sources of trust can evolve fluidly with a
project. For example, you might add a key when you get a new laptop and revoke
that key if your laptop is lost or stolen, but other people can still verify the
old releases signed by the previous key.

# example

generate a key and store it in the db:

``` js
var trust = require('trust-log');
var level = require('level')
var sodium = require('sodium').api
var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var keypair = sodium.crypto_sign_keypair()
var value = {
  secretKey: keypair.secretKey.toString('hex'),
  publicKey: keypair.publicKey.toString('hex')
}

var db = level(argv.d, { valueEncoding: 'json' })
db.put('key', value, function (err) {
  if (err) console.error(err)
})
```

add another trusted key:

``` js
var trust = require('trust-log');
var level = require('level')
var sodium = require('sodium')
var hsodium = require('hyperlog-sodium')

var minimist = require('minimist')
var argv = minimist(process.argv.slice(2))

var db = level(argv.d, { valueEncoding: 'json' })
db.get('key', function (err, value) {
  var keypair = {
    secretKey: Buffer(value.secretKey, 'hex'),
    publicKey: Buffer(value.publicKey, 'hex')
  }
  var log = trust(db, hsodium(sodium, keypair, {
    publicKey: function (id, cb) { log.isTrusted(id, cb) }
  }))
  log.trust(argv._[0], function (err) {
    if (err) console.error(err)
  })
})
```

# methods

``` js
var trust = require('trust-log')
```

## var log = trust(db, opts)

Create a new trusted `log` with a levelup handle `db` and:

* `opts.identity` - the public key of the current node
* `opts.sign` - a signing function for the desired crypto
* `opts.verify` - a verification function for the desired crypto

Optionally set `opts.tofu` to `true` to set "trust on first use" mode.
This mode trusts the first replicated key during replication if the log is empty.

Using [sodium](https://npmjs.com/package/sodium) you can do:

```
var hsodium = require('hyperlog-sodium')
var sodium = require('sodium')
var opts = hsodium(sodium, keypair)
```

to generate the appropriate `opts` for a sodium `keypair`.

## log.trust(id, cb)

Add trust for an identity/publicKey `id`.

## log.revoke(id, cb)

Revoke trust for an identity/publicKey `id`.

## log.trusted(from=null, cb)

Obtain a list of trusted nodes at `from` point in history or the most recent
when `null` as `cb(err, ids)` for an array of `ids`.

## log.isTrusted(from=null, id, cb)

Compute whether the identity/publicKey `id` is trusted at `from` as
`cb(err, ok)`.

## log.verify(from=null, node, cb)

Compute whether a hyperlog `node` is correctly signed with an identity trusted
at `from` as `cb(err, ok)`.

## var r = log.replicate(opts)

Return a full-duplex replication stream `r` for the underlying hyperlog.
`opts` are passed through to hyperlog's `replicate()` after the indexes have
caught up.

# install

With [npm](https://npmjs.com) do:

```
npm install trust-log
```

# thanks

Thanks to [blockai](https://blockai.com) for sponsoring this project.

# license

MIT
