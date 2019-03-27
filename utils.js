//
//  utils.js
//
//  Copyright © 2018 Trusted Key Solutions. All rights reserved.
//

const Crypto = require('crypto')
const CryptoJS = require('crypto-js')
const Assert = require('assert')
const Jsrsasign = require('jsrsasign')
const URL = require('url')
const Moment = require('moment')
const JWT = require('jsonwebtoken')

const CrytoAlg = new Map([
  ['SHA256withRSA', 'RSA-SHA256'],
  ['SHA256withECDSA', 'sha256'],
  ['SHA1withRSA', 'RSA-SHA1']
])
/**
 * Static Trustedkey utility functions
 *
 * @exports utils
*/
const utils = module.exports

/**
 * Add new query parameters to an existing URL.
 * @param {String} path the current url (may be relative)
 * @param {?Object} [params] object with new query parameters
 * @returns {String} new URL with the query parameters merged
 */
utils.mergeQueryParams = function (path, params) {
  Assert.strictEqual(typeof path, 'string', 'path must be of type `string`')
  Assert.strictEqual(typeof params, 'object', 'params must be of type `object`')

  const url = URL.parse(path, true)
  Object.keys(params || {})
    .filter(key => params[key] !== undefined)
    .forEach(key => { url.query[key] = params[key] })
  delete url.search // force recreation from .query
  return url.format()
}

/**
 * Get the SHA256 of the specified blob
 *
 * @param {String|Buffer} blob String or Buffer
 * @param {String} [encoding] Optional encoding for the final digest
 * @returns {Buffer|String} Buffer or string with SHA256
 */
utils.sha256 = function (blob, encoding) {
  const hash = Crypto.createHash('sha256')
  return hash.update(blob).digest(encoding)
}

/**
 * Get the SHA3/KECCAK256 of the specified blob
 *
 * @param {String|Buffer} blob String or Buffer
 * @param {String} [encoding] Optional encoding for the final digest
 * @returns {Buffer|String} Buffer or string with SHA3/KECCAK256
 */
utils.keccak256 = function (blob, encoding) {
  Assert.ok(encoding == null || encoding === 'hex' || encoding === 'base64', 'encoding should be `hex` or undefined')

  if (blob instanceof Buffer) {
    blob = CryptoJS.enc.Base64.parse(blob.toString('base64'))
  }

  const digest = CryptoJS.SHA3(blob, {outputLength: 256})
  if (encoding === 'hex') {
    return digest.toString(CryptoJS.enc.Hex)
  } else if (encoding === 'base64') {
    return digest.toString(CryptoJS.enc.Base64)
  } else {
    return Buffer.from(digest.toString(CryptoJS.enc.Base64), 'base64')
  }
}

function pad0 (string, len) {
  return String('0'.repeat(len) + string).slice(-len)
}

/**
 * Convert a certificate serial number to blockchain address
 *
 * @param {String} serialhex Hex encoded serial number
 * @returns {String} 0x prefixed address
 */
utils.serialToAddress = function (serialhex) {
  Assert.strictEqual(typeof serialhex, 'string', 'serialhex must be of type `string`')

  return '0x' + pad0(serialhex, 40)
}

/**
 * Base64 encode URL string
 *
 * @param {String|Uint8Array|Array} data data to encode
 * @param {String} [encoding] Optional encoding of data
 * @returns {String} base64-encoded URL
 */
utils.base64url = function (data, encoding) {
  return Buffer.from(data, encoding).toString('base64').replace(/=/g, '').replace(/\//g, '_').replace(/\+/g, '-')
}

/**
 * Get UTC seconds since UNIX epoch or convert date into unix time
 *
 * @param {Date} [date] Optional date object
 * @returns {Number} Unix timestamp
 */
utils.getUnixTime = function (date) {
  return Math.floor((date || new Date()).getTime() / 1000)
}

/**
 * Create a JSON Web Signature
 *
 * @deprecated
 * @param {object|String|Buffer} message Message can be string or object. Objects will be JSON stringified
 * @param {String} secret HMAC shared secret
 * @param {object} [header={alg: "HS256"}] JOSE header OPTIONAL
 * @returns {String} Signed JWS
 */
utils.createHmacJws = function (message, secret, header = {}) {
  Assert.strictEqual(typeof secret, 'string', 'secret must be of type `string`')
  Assert.strictEqual(typeof header, 'object', 'header must be of type `object`')

  const options = {header, algorithm: 'HS256'}
  return JWT.sign(message, secret, options)
}

/**
 * Create a JSON Web Signature
 *
 * @deprecated
 * @param {object|String|Buffer} message Message can be string or object. Objects will be JSON stringified
 * @param {object} credential key pair
 * @param {object} [header={alg: "ES256"}] JOSE header OPTIONAL
 * @returns {String} Signed JWS
 */
utils.createEcdsaJws = function (message, credential, header = {}) {
  Assert.strictEqual(typeof credential, 'object', 'credential must be of type `object`')
  Assert.strictEqual(typeof header, 'object', 'header must be of type `object`')

  const jwk = utils.hexToJwk(credential.pubKeyHex)
  // Add the private key to the public key JWK
  jwk.d = utils.base64url(credential.prvKeyHex, 'hex')
  const pem = utils.jwkToPem(jwk)
  const options = {header, algorithm: 'ES256'}
  return JWT.sign(message, pem, options)
}

/**
 * Verify a JSON Web Signature.
 *
 * @deprecated
 * @param {String} jws the JWS or JWT as string
 * @param {String|function|Object} secretOrCallback Shared secret or public key
 * @returns {Object|String|null} the parsed claims or `null` on failure
 */
utils.verifyJws = function (jws, secretOrCallback) {
  Assert.strictEqual(typeof jws, 'string', 'jws must be of type `string`')

  // Convert the given secret into a secret or public key for jsonwebtoken,
  if (typeof secretOrCallback === 'function') {
    // JWT.verify will no longer return a value if we use the callback overload
    const decoded = JWT.decode(jws, {complete: true})
    // Removed promise support since it was never actually used anywhere
    secretOrCallback = secretOrCallback(decoded.header)
  }
  if (typeof secretOrCallback === 'object' && secretOrCallback.pubKeyHex) {
    // Convert jsrsasign credential to hex public key
    secretOrCallback = secretOrCallback.pubKeyHex
  }
  if (typeof secretOrCallback === 'string' && secretOrCallback.length === 130) {
    // Convert uncompressed hex public key to JWK
    secretOrCallback = utils.hexToJwk(secretOrCallback)
  }
  if (typeof secretOrCallback === 'object' && secretOrCallback.kty) {
    // Convert JWK to PEM public key
    secretOrCallback = utils.jwkToPem(secretOrCallback)
  }

  try {
    return JWT.verify(jws, secretOrCallback)
  } catch (err) {
    // Keep the old behavior of returning null instead of throwing
    if (err.name === 'JsonWebTokenError') {
      return null
    } else {
      throw err
    }
  }
}

/**
 * @typedef JwkEC
 * @type {object}
 * @property {'EC'} kty Key Type
 * @property {'P-256'} crv Elliptic Curve
 * @property {string} x Base64-URL encoded X coordinate
 * @property {string} y Base64-URL encoded Y coordinate
 * @property {string} [d] Base64-URL encoded private key
 *
 * @typedef JwkRSA
 * @type {object}
 * @property {'RSA'} kty Key Type
 * @property {string} e Base64-URL encoded exponent
 * @property {string} n Base64-URL encoded modulus
 */

/**
 * Convert a JWK into a hex public key
 * @param {JwkEC} jwk JSON Web Key for public EC key
 * @return {String} string with hex public key
 */
utils.jwkToHex = function (jwk) {
  Assert.strictEqual(jwk.d, undefined, 'jwk.d must be of type `undefined`')
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    // Convert x,y coordinates from JWK to hex encoded public key
    const hex = '04' + Buffer.concat([Buffer.from(jwk.x, 'base64'), Buffer.from(jwk.y, 'base64')]).toString('hex')
    Assert.strictEqual(hex.length, 130)
    return hex
  } else if (jwk.kty === 'RSA' && jwk.e === 'AQAB') {
    return Buffer.from(jwk.n, 'base64').toString('hex')
  }
  throw Error('Unsupported JWK:' + jwk)
}

/**
 * Convert a hex key into JWK
 * @param {String} keyHex hex encoded ECC key
 * @param {String} [crv] curve identifier ("P-256" by default)
 * @return {JwkEC} JSON Web Key
 */
utils.hexToJwk = function (keyHex, crv = 'P-256') {
  Assert.strictEqual(typeof keyHex, 'string', 'pubKeyHex must be of type `string`')

  const buffer = Buffer.from(keyHex, 'hex')
  if (buffer.length === 65) {
    Assert.ok(keyHex.startsWith('04'), 'pubKeyHex must be an uncompressed ECC public key')
    return {
      crv,
      'kty': 'EC',
      'x': utils.base64url(buffer.slice(1, 33)),
      'y': utils.base64url(buffer.slice(33))
    }
  } else {
    throw Error('Unsupported key: ' + keyHex)
  }
}

function createDerChunk (tag, ...nested) {
  let header
  const size = nested.reduce((p, b) => p + b.length, 0)
  if (size < 0x80) {
    header = Buffer.alloc(2)
    header.writeUInt8(size, 1)
  } else if (size < 0x100) {
    header = Buffer.alloc(3)
    header.writeUInt8(0x81, 1)
    header.writeUInt8(size, 2)
  } else {
    Assert.ok(size <= 0xffff, 'Invalid PEM size: ' + size)
    header = Buffer.alloc(4)
    header.writeUInt8(0x82, 1)
    header.writeUInt16BE(size, 2)
  }
  header.writeUInt8(tag)
  return Buffer.concat([header, ...nested])
}

function readDerChunk (buffer, offset = 0) {
  offset++
  let size = buffer.readUInt8(offset++)
  if (size === 0x81) {
    size = buffer.readUInt8(offset++)
    Assert.ok(size >= 0x80, 'Invalid PEM size: ' + size)
  } else if (size === 0x82) {
    size = buffer.readUInt16BE(offset)
    Assert.ok(size >= 0x100, 'Invalid PEM size: ' + size)
    offset += 2
  } else {
    Assert.ok(size < 0x80, 'Invalid PEM size: ' + size)
  }
  return buffer.slice(offset, offset + size)
}

/**
 * Convert a PEM encoded public key to JWK, with minimal checking.
 * @param {string} pem Public key in PEM format
 * @returns {JwkRSA|JwkEC} JSON Web Key
 */
utils.pemToJwk = function (pem) {
  const base64 = pem.match(/^-----BEGIN [A-V ]{6,10} KEY-----([^-]+)-----END [A-V ]{6,10} KEY-----/)
  if (!base64) {
    throw Error('Unsupported PEM:' + pem)
  }
  const der = Buffer.from(base64[1], 'base64')
  return utils.derToJwk(der)
}

/**
 * Convert a DER encoded public key to JWK, with minimal checking.
 * @param {Buffer} der Public key in DER format
 * @returns {JwkRSA|JwkEC} JSON Web Key
 */
utils.derToJwk = function (der) {
  const main = readDerChunk(der)
  const type = readDerChunk(main)
  const key = readDerChunk(main, type.length + 2)
  switch (type.toString('hex')) {
    case '06092a864886f70d0101010500': {
      // RSA public
      const rsa = readDerChunk(key, 1)
      const n = readDerChunk(rsa).slice(1)
      const lenSize = n.length >= 0x100 ? 3 : (n.length >= 0x80 ? 2 : 1)
      const e = readDerChunk(rsa, n.length + lenSize + 2)
      return {
        'kty': 'RSA',
        'e': utils.base64url(e),
        'n': utils.base64url(n)
      }
    }
    case '06072a8648ce3d020106082a8648ce3d030107': {
      // EC public
      Assert.strictEqual(key.length, 66)
      const x = key.slice(2, 34)
      const y = key.slice(34, 66)
      return {
        'crv': 'P-256',
        'kty': 'EC',
        'x': utils.base64url(x),
        'y': utils.base64url(y)
      }
    }
    case '00': {
      // EC private (nested)
      const nested = readDerChunk(main, 5 + key.length)
      return utils.derToJwk(nested)
    }
    case '01': {
      // EC private
      let skip = 5 + key.length
      while (main[skip] !== 0xa1) {
        skip += 2 + readDerChunk(main, skip).length
      }
      const pub = readDerChunk(main, 2 + skip)
      Assert.strictEqual(pub.length, 66)
      const x = pub.slice(2, 34)
      const y = pub.slice(34, 66)
      return {
        'crv': 'P-256',
        'kty': 'EC',
        'd': utils.base64url(key, 'hex'),
        'x': utils.base64url(x),
        'y': utils.base64url(y)
      }
    }
    default:
      throw Error('Unsupported PEM type:' + type.toString('hex'))
  }
}

function wrap (str) {
  return str.replace(/(.{64})/g, '$1\n')
}

/**
 * Convert a JWK into a hex public key
 * @param {JwkEC|JwkRSA} jwk JSON Web Key for public EC key
 * @return {String} string with PEM public key
 */
utils.jwkToPem = function (jwk) {
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    // Convert x,y coordinates from JWK to public key
    const xy = Buffer.concat([Buffer.from(jwk.x, 'base64'), Buffer.from(jwk.y, 'base64')])
    Assert.strictEqual(xy.length, 64)
    if (jwk.d) {
      // Add the private key as well
      const header = Buffer.from('30770201010420', 'hex')
      const pk = Buffer.from(jwk.d, 'base64')
      const xyhdr = Buffer.from('a00a06082a8648ce3d030107a14403420004', 'hex')
      const all = Buffer.concat([header, pk, xyhdr, xy])
      return wrap(`-----BEGIN EC PRIVATE KEY-----
${all.toString('base64')}
-----END EC PRIVATE KEY-----`)
    } else {
      // Basic template for the PEM; we'll overwrite the coordinates in-place
      return wrap(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${xy.toString('base64')}
-----END PUBLIC KEY-----`)
    }
  } else if (jwk.kty === 'RSA') {
    // Convert public key from JWK to base64 encoded public key
    const pub = Buffer.from(jwk.n, 'base64')
    const exp = Buffer.from(jwk.e, 'base64')
    const pubDer = createDerChunk(0x02, Buffer.alloc(1), pub)
    const expDer = createDerChunk(0x02, exp)
    const key = createDerChunk(0x30, pubDer, expDer)
    const pkey = createDerChunk(0x03, Buffer.alloc(1), key)
    const der = createDerChunk(0x30, Buffer.from('300d06092a864886f70d0101010500', 'hex'), pkey)
    return wrap(`-----BEGIN PUBLIC KEY-----
${der.toString('base64')}
-----END PUBLIC KEY-----`)
  }
  throw Error('Unsupported JWK:' + jwk)
}

/**
 * Verify an ECDSA named curve signed message
 *
 * @param {String} curveName Curve name (secp256r1)
 * @param {String} message Message payload
 * @param {String|Object} pubkey Public key to check signature against (hex)
 * @param {Buffer|String} signature Signature payload (hex)
 * @return {boolean} Indicate whether signature is correct
 */
utils.checkECDSA = function (curveName, message, pubkey, signature) {
  Assert.strictEqual(typeof curveName, 'string', 'curveName must be of type `string`')

  // Verify a digest value
  var digest = utils.sha256(message, 'hex')

  if (pubkey.kty) {
    pubkey = utils.jwkToHex(pubkey)
  } else if (pubkey.pubKeyHex) {
    pubkey = pubkey.pubKeyHex
  }
  if (signature instanceof Buffer) {
    signature = signature.toString('hex')
  }

  // Convert r||s signatures to proper DER
  if (signature.length === 128 && !/^303e02/i.test(signature)) {
    const r = Buffer.from(signature.substr(0, 64), 'hex')
    const s = Buffer.from(signature.substr(64), 'hex')
    signature = createDerChunk(0x30, createDerChunk(0x02, r), createDerChunk(0x02, s)).toString('hex')
  }

  var curve = new Jsrsasign.KJUR.crypto.ECDSA({xy: pubkey, curve: curveName})
  return curve.verifyHex(digest, signature, pubkey)
}

/**
 * Convert a user public key to blockchain address
 *
 * @param {String} pubkeyhex User ECC public key (hex encoded)
 * @returns {String} User address with leading 0x
 */
utils.userPubKeyHexToAddress = function (pubkeyhex) {
  Assert.strictEqual(typeof pubkeyhex, 'string', 'pubkeyhex must be of type `string`')
  Assert.ok(pubkeyhex.startsWith('04'), 'pubkeyhex must be an uncompressed ECC public key')
  Assert.strictEqual(pubkeyhex.length, 130)

  // Get the uncompressed public key without prefix, take the sha256 hash, and skip the first 12 bytes
  var blob = Buffer.from(pubkeyhex.substr(2), 'hex')
  var digest = utils.sha256(blob, 'hex')
  return '0x' + digest.substr(2 * 12)
}

/**
 * Wrap the call and change the callback into a promise resolve or reject.
 * @param {function} call A function that takes a callback as last parameter
 * @returns {function} Wrapper function that returns a promise
 */
utils.promisify = function (call) {
  return function () {
    // Save the 'this' reference for use inside the promise
    var self = this
    var args = Array.prototype.slice.call(arguments)
    return new Promise((resolve, reject) => {
      // Append the callback that either rejects or resolves the promise
      args.push((err, a, b, c, d) => err ? reject(err) : resolve(a, b, c, d))
      call.apply(self, args)
    })
  }
}

/**
 * Generate a 32-byte random nonce.
 * @param {String} [encoding] Encoding for result (default base64)
 * @param {Number} [length] Number of bytes for the result (default 32)
 * @returns {String} The encoding of the nonce
 */
utils.generateNonce = function (encoding, length) {
  return Crypto.randomBytes(length || 32).toString(encoding || 'base64')
}

/**
 * Wait for specified number of milliseconds (ms).
 * @param {Number} durationMS Number of milliseconds to wait.
 * @return {Promise} Promise that resolves in due time.
 */
utils.wait = function (durationMS) {
  return new Promise((resolve, reject) => {
    return setTimeout(resolve, durationMS)
  })
}

/**
 * Wait until the callback returns a truthy value (or timeout).
 * @param {Number} ms Number of milliseconds to wait.
 * @param {function} callback Callback to invoke (once a second).
 * @param {Number} [step] Number of milliseconds to wait per try.
 * @return {Promise} Promise that resolves when the callback is truthy
 */
utils.waitUntil = function (ms, callback, step = 1000) {
  Assert.strictEqual(typeof ms, 'number', 'ms must be of type `number`')
  Assert.strictEqual(typeof callback, 'function', 'callback must be of type `function`')
  Assert.ok(step > 0, 'step must be of type `number` > 0')
  return Promise.resolve()
    .then(callback)
    .then(done => {
      if (done || ms <= 0) {
        return done
      }
      return utils.wait(Math.min(step, ms))
        .then(() => utils.waitUntil(ms - step, callback, step))
    })
}

/**
 * Generate a new key pair.
 * @param {string|number} [curveOrLength] The name of the EC curve or RSA modulus length (optional)
 * @return {Promise.<Object>} New jsrsasign key object of given curve
 */
utils.generateKeyPair = async function (curveOrLength) {
  let pair
  try {
    const {promisify} = require('util')
    const keyOptions = Object.assign(curveOrLength > 0 ? { modulusLength: curveOrLength } : { namedCurve: curveOrLength || 'prime256v1' },
      {
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      })
    const {privateKey} = await promisify(Crypto.generateKeyPair)(
      curveOrLength > 0 ? 'rsa' : 'ec',
      keyOptions
    )
    pair = Jsrsasign.KEYUTIL.getKey(privateKey)
  } catch (err) {
    pair = Jsrsasign.KEYUTIL.generateKeypair(curveOrLength > 0 ? 'RSA' : 'EC', curveOrLength || 'secp256r1').prvKeyObj
  }

  return {
    prvKeyHex: pair.prvKeyHex,
    pubKeyHex: pair.pubKeyHex
  }
}

/**
 * HMAC-based One-time Password Algorithm
 * @param {string|Buffer} key The shared key for the HMAC.
 * @param {string|Buffer} message The message (64-bit counter or 32-bit time/30)
 * @return {string} six digit HOTP code
 */
utils.oneTimePassword = function (key, message) {
  const hash = Crypto.createHmac('sha1', key).update(message).digest()
  const offset = hash[hash.length - 1] & 0xf
  // 4 bytes starting at the offset, remove the most significant bit
  const truncatedHash = hash.readInt32BE(offset) & 0x7FFFFFFF // big endian
  const code = truncatedHash % 1000000
  // pad code with 0 until length of code is 6;
  return String('00000' + code).slice(-6)
}

/**
 * Decode a string with HEX-encoded data into a plain binary string.
 * @param {string} hex String with HEX-encoded data
 * @param {string} [encoding='binary'] Optional encoding of the data
 * @returns {string} String with binary encoded data
 */
utils.parseHexString = function (hex, encoding) {
  Assert.strictEqual(typeof hex, 'string', 'hex must be of type `string`')
  return Buffer.from(hex, 'hex').toString(encoding || 'binary')
}

/**
 * Parse ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ into a Date object.
 * @param {string} date ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ date string.
 * @returns {?Date} New date object or `null` for invalid dates
 */
utils.parseX509Date = function (date) {
  Assert.strictEqual(typeof date, 'string', 'date must be of type `string`')

  var match = /^([0-9]{2,4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/.exec(date)
  if (match === null) {
    return null
  }
  // - Where YY is less than 50, the year shall be interpreted as 20YY.
  const year = match[1].length === 2 && match[1] < 50 ? 2000 + parseInt(match[1]) : match[1]
  return new Date(Date.UTC(year, match[2] - 1, match[3], match[4], match[5], match[6]))
}

/**
 * Create ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ into a string.
 * @param {Date} date Date object.
 * @returns {string} New ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ date string
 */
utils.dateToString = function (date) {
  if (date.getFullYear() < 1950 || date.getFullYear() > 2049) {
    return Moment(date).utc().format('YYYYMMDDHHmmss[Z]', date)
  } else {
    return Moment(date).utc().format('YYMMDDHHmmss[Z]', date)
  }
}

/**
 * Check whether the given string is a valid blockchain address.
 * @param {string} str The string to check for 0x-prefixed address
 * @returns {boolean} `true` if the string is a valid address; false otherwise.
 */
utils.isAddress = function (str) {
  Assert.strictEqual(typeof str, 'string', 'str must be of type `string`')
  return /^0x[0-9a-fA-F]{40}$/.test(str)
}

/**
 * @param {string} pem PEM string
 * @returns {Jsrsasign.X509} certificate
 */
function readPEM (pem) {
  Assert.strictEqual(typeof pem, 'string', 'pem must be of type `string`')
  // Ignore PEM headers (if present)
  const base64 = pem.replace(/^-----(BEGIN|END) CERTIFICATE-----/g, '')
  // Load the certificate from PEM string
  var cert = new Jsrsasign.X509()
  cert.readCertHex(Buffer.from(base64, 'base64').toString('hex'))
  return cert
}

/**
 * @param {Jsrsasign.X509} cert certificate
 * @param {Jsrsasign.X509} caCert CA certificate
 * @returns {boolean} success or failure
 */
function verifySignature (cert, caCert) {
  try {
    const algName = cert.getSignatureAlgorithmName()
    const cryptoAlg = CrytoAlg.get(algName)
    if (cryptoAlg == null) {
      throw Error(`Unsupported signature algorithm: ${algName}`)
    }
    const hSigVal = Buffer.from(cert.getSignatureValueHex(), 'hex')
    const tbs = Buffer.from(Jsrsasign.ASN1HEX.getTLVbyList(cert.hex, 0, [0], '30'), 'hex')
    const verify = Crypto.createVerify(cryptoAlg)
    verify.update(tbs)
    const caPem = Jsrsasign.KEYUTIL.getPEM(caCert.getPublicKey())
    return verify.verify(caPem, hSigVal)
  } catch (err) {
    throw Error(`Invalid PEM: ${err}`)
  }
}

/**
 * @typedef Attribute
 * @type {object}
 * @property {string} oid The OID path for this attribute
 * @property {string} value The value of this attribute
 *
 * @typedef Claim
 * @type {object}
 * @property {string} subjectaddress The public key hash
 * @property {string} serialNo
 * @property {string} issuer The X.500 issuer name
 * @property {?string} issuerPem The issuer X.509 PEM
 * @property {Array.<string>} ocsp Array of OCSP responders
 * @property {Array.<string>} caissuer Array of issuers
 * @property {Array.<string>} crl Array of CRL distribution URIs
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {Array.<Attribute>} attributes The array of attributes of this claim
 **/

/**
 * Parse a PEM encoded X509 certificate.
 * @param {string} pem The X509 certificate in PEM format
 * @param {Array.<string>} [chain] The X509 certificates of the CA chain
 * @returns {Claim} The parsed X509 certificate
 */
utils.parsePem = function (pem, chain) {
  // Load the certificate from PEM string
  var cert = readPEM(pem)

  // Validate certificate chain (issuer whitelist)
  let issuerPem = null
  if (chain) {
    issuerPem = chain.find(caPem => verifySignature(cert, readPEM(caPem)))
    if (issuerPem == null) {
      throw Error('Signature verification failed')
    }
  }

  const serialNo = utils.serialToAddress(cert.getSerialNumberHex())
  const issuer = cert.getIssuerString()
  const ocsp = cert.getExtAIAInfo() || {caissuer: [], ocsp: []}
  const crl = cert.getExtCRLDistributionPointsURI() || []

  const subjectPubkey = cert.getPublicKey().pubKeyHex
  const subjectaddress = subjectPubkey !== undefined ? utils.userPubKeyHexToAddress(subjectPubkey) : undefined

  const notAfter = utils.parseX509Date(cert.getNotAfter())
  const notBefore = utils.parseX509Date(cert.getNotBefore())

  // Extract the token information from the DName
  const attributes = []
  try {
    for (let d = 0; ; d++) {
      const tlv = Jsrsasign.ASN1HEX.getTLVbyList(cert.hex, 0, [0, 5, d])
      const oidHex = Jsrsasign.ASN1HEX.getVbyList(tlv, 0, [0, 0])
      if (oidHex === '') break
      const valueHex = Jsrsasign.ASN1HEX.getVbyList(tlv, 0, [0, 1])
      // CONSIDER: use encoding based on ASN.1 value type
      const value = utils.parseHexString(valueHex, 'utf-8')

      const oid = Jsrsasign.ASN1HEX.hextooidstr(oidHex)
      attributes.push({oid, value})
    }
  } catch (err) {}

  return Object.assign({subjectaddress, serialNo, notBefore, notAfter, attributes, issuer, crl, issuerPem}, ocsp)
}

/**
 * Validate the parsed claim
 * @param {Claim} claim Parsed claim object
 * @param {Date} [date] Optional date to test against
 * @returns {Boolean} success or failure
 */
utils.validateClaim = function (claim, date) {
  Assert.strictEqual(typeof claim, 'object', 'claim must be of type `object`')

  const now = date || new Date()
  if (claim.notAfter < now) {
    return false
  }
  if (claim.notBefore > now) {
    return false
  }
  if (claim.issuerPem) {
    // Rescursively validate the issuer
    const issuerClaim = utils.parsePem(claim.issuerPem)
    return utils.validateClaim(issuerClaim, now)
  }
  return true
}

/**
 * Return the absolute path to the Trusted Key root CA certificate.
 * @returns {string} Absolute path to the Trusted Key root CA certificate
 */
utils.getRootPemPath = function () {
  return require('path').join(__dirname, 'tkroot.pem')
}

/**
 * Get the JWK thumbprint for the given key.
 * @param {JwkEC|JwkRSA} jwk JSON Web Key
 * @returns {string} Base64-URL encoded thumbprint for the JWK
 */
utils.getJwkThumbprint = function (jwk) {
  // Only the required members of a key's representation are used when computing its JWK Thumbprint value.
  const json = JSON.stringify(jwk, ['crv', 'e', 'k', 'kty', 'n', 'x', 'y'])
  return this.base64url(utils.sha256(json))
}

/**
 * Verify x5c X509 cert chain
 * @param {Array.string} chain encoded BASE64 PEMs in x5c
 * @return {boolean} evaluation of chain validation
 */
utils.verifyChain = function (chain) {
  Assert.ok(Array.isArray(chain), 'chain must be instance of `Array`')

  const certs = chain.map(p => readPEM(p))
  const getCAIdx = (i) => (i === certs.length - 1) ? i : i + 1
  for (let i = 0; i < certs.length; i++) {
    if (!verifySignature(certs[i], certs[getCAIdx(i)])) {
      return false
    }
  }

  return true
}
