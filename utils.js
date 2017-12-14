//
//  utils.js
//
//  Copyright © 2017 Trusted Key Solutions. All rights reserved.
//

const Crypto    = require('crypto')
const Assert    = require('assert')
const Jsrsasign = require('jsrsasign')
const URL       = require('url')

/**
 * Static Trustedkey utility functions
 *
 * @exports utils
*/
const utils = module.exports = {}


/**
 * Add new query parameters to an existing URL.
 * @param {String} path - the current url (may be relative)
 * @param {Object} params - object with new query parameters
 * @returns {String} new URL with the query parameters merged
 */
utils.mergeQueryParams = function(path, params) {

    Assert.strictEqual(typeof path, "string", `path must be of type "string"`)
    Assert.strictEqual(typeof params, "object", `params must be of type "object"`)

    const url = URL.parse(path, true)
    Object.keys(params||{})
        .filter(key => params[key] !== undefined)
        .forEach(key => url.query[key] = params[key])
    delete url.search   // force recreation from .query
    return url.format()
}


/**
 * Get the SHA256 of the specified blob
 *
 * @param {String|Buffer} blob - String or Buffer
 * @param {String} encoding - OPTIONAL
 * @returns {Buffer} Buffer with SHA256
 */
utils.sha256 = function(blob, encoding) {
    var hash = Crypto.createHash('sha256')
    return hash.update(blob).digest(encoding)
}

/**
 * Convert a certificate serial number to blockchain address
 *
 * @param {String} serialhex - Hex encoded serial number
 * @returns {String} 0x prefixed address
 */
utils.serialToAddress = function(serialhex) {

    Assert.strictEqual(typeof serialhex, "string", `serialhex must be of type "string"`)

    const paddedSerial = String('00000000000000000000000000000000000000'+serialhex).slice(-40)
    return "0x" + paddedSerial
}

/**
 * Base64 encode URL string
 *
 * @param {String} data - URL string to encode
 * @param {String} encoding - (optional) encoding of data
 * @returns {String} base64-encoded URL
 */
utils.base64url = function(data, encoding) {
    return Buffer.from(data, encoding).toString("base64").replace(/=/g,'').replace(/\//g,'_').replace(/\+/g,'-')
}

/**
 * Get UTC seconds since UNIX epoch or convert date into unix time
 *
 * @param {Date} date - Optional date object
 * @returns {Number} Unix timestamp
 */
utils.getUnixTime = function(date) {
    return Math.floor((date||new Date).getTime()/1000)
}


/**
 * Create a JSON Web Signature
 *
 * @param {object|String} message - Message can be string or object. Objects will be JSON stringified
 * @param {String} secret - HMAC shared secret
 * @param {object} [header={alg: "HS256"}] - JOSE header OPTIONAL
 * @returns {String} Concatenated JWS HMAC
 */
utils.createHmacJws = function(message, secret, header) {
    if (typeof message !== 'string') {
        message = JSON.stringify(message)
    }
    if (typeof header === 'undefined') {
        header = {}
    }
    header.alg = "HS256"
    const jose = JSON.stringify(header)
    const jws = utils.base64url(jose) + '.' + utils.base64url(message)
    const hmac = Crypto.createHmac('sha256', secret)
    return jws + '.' + utils.base64url(hmac.update(jws, secret).digest())
}


/**
 * Create a JSON Web Signature
 *
 * @param {object|String} message - Message can be string or object. Objects will be JSON stringified
 * @param {object} credential - key pair
 * @param {object} [header={alg: "ES256"}] - JOSE header OPTIONAL
 * @returns {String} Concatenated JWS
 */
utils.createEcdsaJws = function(message, credential, header) {
    if (typeof message !== 'string') {
        message = JSON.stringify(message)
    }
    if (typeof header === 'undefined') {
        header = {}
    }
    header.alg = "ES256"
    const jose = JSON.stringify(header)
    const jws = utils.base64url(jose) + '.' + utils.base64url(message)
    // Sign a digest value
    const sig = credential.signWithMessageHash(utils.sha256(jws, 'hex'))
    return jws + '.' + utils.base64url(Buffer.from(sig,'hex'))
}


/**
 * Verify a JSON Web Signature
 *
 * @param {String} jws the JWT or JWT as string
 * @param {String|Promise|function} secretCallback HMAC shared secret or public key
 * @returns {Object} the parsed claims or `null`
 */
utils.verifyJws = function(jws, secretCallback) {

    Assert.strictEqual(typeof jws, "string", `jws must be of type "string"`)

    const parts = jws.split(/\./g)
    if (parts.length !== 3) {       // JWE has 5 parts
        return null
    }

    const jose = JSON.parse(Buffer.from(parts[0], "base64"))
    const message = Buffer.from(parts[1], "base64")
    const signature = Buffer.from(parts[2], "base64")
    const signeddata = parts[0] + '.' + parts[1]

    function verify(secret) {
        if (jose.alg === 'ES256') {
            // ECDSA-SHA256
            const payload = JSON.parse(message)
            // OLD: Subject public key was stored in 'sub' claim
            var pubkeyhex = secret || payload.sub || utils.jwkToHex(jose.jwk)
            if (utils.checkECDSA("secp256r1", signeddata, pubkeyhex, signature)) {
                return payload
            }
        }
        else if (jose.alg === 'HS256') {
            // HMAC-SHA256
            const hmac = Crypto.createHmac('sha256', secret)
            if (hmac.update(signeddata).digest().equals(signature)) {
                // Verify any nested JWT
                if (jose.cty === "JWT") {
                    return utils.verifyJws(message, secretCallback)
                }
                else {
                    return JSON.parse(message)
                }
            }
        }
        else if (jose.alg === 'RS256') {
            // TODO
        }
        else if (jose.alg === 'none') {
            // NONE, only allow if callback returns empty string
            if (signature === '' && secret === '') {
                return JSON.parse(message)
            }
        }
        return null
    }

    const secret = typeof secretCallback === "function" ? secretCallback(jose) : secretCallback
    if (typeof secret.then === "function") {
        return secret.then(verify)
    }
    else {
        return verify(secret)
    }
}


/**
 * Convert a JWK into a hex public key
 * @param {String} jwk - JSON Web Key for public EC key
 * @return {String} string with hex public key
 */
utils.jwkToHex = function(jwk) {

    if (jwk.crv === "P-256" && jwk.kty === "EC") {
        Assert.strictEqual(typeof jwk.d, "undefined", `jwk.d must be of type "undefined"`)
        // Convert x,y coordinates from JWK to hex encoded public key
        const hex = "04" + Buffer.from(jwk.x, "base64").toString("hex") + Buffer.from(jwk.y, "base64").toString("hex")
        Assert.strictEqual(hex.length, 130)
        return hex
    }
    Assert(false, "Unsupported JWK:"+jwk)
}


/**
 * Convert a hex public key into JWK
 * @param {String} pubKeyHex - hex encoded public key
 * @return {String} JSON Web Key
 */
utils.hexToJwk = function(pubKeyHex) {
    Assert.strictEqual(pubKeyHex.length, 130)
    Assert(pubKeyHex.startsWith("04"))

    const buffer = Buffer.from(pubKeyHex, 'hex')
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": utils.base64url(buffer.slice(1,33)),
        "y": utils.base64url(buffer.slice(33)),
    }
}


/**
 * Convert a JWK into a hex public key
 * @param {String} jwk - JSON Web Key for public EC key
 * @return {String} string with PEM public key
 */
utils.jwkToPem = function(jwk) {

    if (jwk.crv === "P-256" && jwk.kty === "EC") {
        Assert.strictEqual(typeof jwk.d, "undefined", `jwk.d must be of type "undefined"`)
        // Convert x,y coordinates from JWK to base64 encoded public key
        const all = Buffer.concat([Buffer.from(jwk.x, "base64"), Buffer.from(jwk.y, "base64")]).toString("base64")
        Assert.strictEqual(all.length, 88)
        // Basic template for the PEM; we'll overwrite the coordinates in-place
        return `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${all}
-----END PUBLIC KEY-----`
    }
    Assert(false, "Unsupported JWK:"+jwk)
}


/**
 * Verify an ECDSA named curve signed message
 *
 * @param {String} curveName - Curve name (secp256r1)
 * @param {String} message - Message payload
 * @param {String|Object} pubkey - Public key to check signature against (hex)
 * @param {Buffer|String} signature - Signature payload (hex)
 * @return {boolean} Indicate whether signature is correct
 */
utils.checkECDSA = function(curveName, message, pubkey, signature) {

    Assert.strictEqual(typeof curveName, "string", `curveName must be of type "string"`)

    // Verify a digest value
    var digest = utils.sha256(message, 'hex')

    if (pubkey.kty) {
        pubkey = utils.jwkToHex(pubkey)
    }
    if (signature instanceof Buffer) {
        signature = signature.toString('hex')
    }

    var curve = new Jsrsasign.KJUR.crypto.ECDSA({xy: pubkey, curve: curveName})
    return curve.verifyHex(digest, signature, pubkey)
}


/**
 * Convert a user public key to blockchain address
 *
 * @param {String} pubkeyhex - User public key (hex encoded)
 * @returns {String} User address with leading 0x
 */
utils.userPubKeyHexToAddress = function(pubkeyhex) {

    Assert.strictEqual(typeof pubkeyhex, "string", `pubkeyhex must be of type "string"`)
    // Sign a digest value
    // Get the uncompressed public key without prefix, take the sha256 hash, and skip the first 12 bytes
    var blob = new Buffer(pubkeyhex.substr(2), 'hex')
    var digest = utils.sha256(blob, 'hex')
    return "0x" + digest.substr(2*12)
}


/**
 * Wrap the call and change the callback into a promise resolve or reject.
 * @param {function} call A function that takes a callback as last parameter
 * @returns {function} Wrapper function that returns a promise
 */
utils.promisify = function(call) {
    return function() {
        // Save the 'this' reference for use inside the promise
        var self = this
        var args = Array.prototype.slice.call(arguments)
        return new Promise( (resolve,reject) => {
            // Append the callback that either rejects or resolves the promise
            args.push( (err,a,b,c,d) => err?reject(err):resolve(a,b,c,d) )
            call.apply(self, args)
        })
    }
}


/**
 * Generate a 32-byte random nonce.
 * @param {String} encoding - Encoding for result (default base64)
 * @param {Number} length - Number of bytes for the result (default 32)
 * @returns {String} The encoding of the nonce
 */
utils.generateNonce = function(encoding, length) {
    return Crypto.randomBytes(length || 32).toString(encoding || 'base64')
}


/**
 * Wait for specified number of milliseconds (ms).
 * @param {Number} duration_ms Number of milliseconds to wait.
 * @return {Promise} Promise that resolves in due time.
 */
utils.wait = function(duration_ms) {
    return new Promise( (resolve, reject) => {
        return setTimeout(resolve, duration_ms)
    })
}


/**
 * Wait until the callback returns a truthy value (or timeout).
 * @param {Number} ms Number of milliseconds to wait.
 * @param {function} callback Callback to invoke (once a second).
 * @return {Promise} Promise that resolves when the callback is truthy
 */
utils.waitUntil = function(ms, callback) {

    Assert.strictEqual(typeof ms, "number", `ms must be of type "number"`)
    Assert.strictEqual(typeof callback, "function", `callback must be of type "function"`)
    return utils.wait(ms > 1000 ? 1000 : ms)
        .then(_ => callback())
        .then(done => {
            ms -= 1000
            if (!done && ms > 0) {
                return utils.waitUntil(ms, callback)
            }
            return done
        })
}


/**
 * Generate a new key pair.
 * @param {string} curveName The name of the EC curve. (optional)
 * @return {Object} New jsrsasign key object of given curve
 */
utils.generateKeyPair = function(curveName) {

    return Jsrsasign.KEYUTIL.generateKeypair("EC", curveName||"secp256r1").prvKeyObj
}


/**
 * HMAC-based One-time Password Algorithm
 * @param {string|Buffer} key The shared key for the HMAC.
 * @param {string|Buffer} message The message (64-bit counter or 32-bit time/30)
 * @return {string} six digit HOTP code
 */
utils.oneTimePassword = function(key, message) {

    const hash = Crypto.createHmac('sha1', key).update(message).digest()
    const offset = hash[hash.length - 1] & 0xf
    //4 bytes starting at the offset, remove the most significant bit
    const truncatedHash = hash.readInt32BE(offset) & 0x7FFFFFFF     // big endian
    const code = truncatedHash % 1000000
    //pad code with 0 until length of code is 6;
    return String("00000" + code).slice(-6)
}


/**
 * Decode a string with HEX-encoded data into a plain binary string.
 * @param {string} hex String with HEX-encoded data
 * @returns {string} String with binary encoded data
 */
utils.parseHexString = function(hex) {

    return decodeURIComponent(hex.replace(/(..)/g,"%$1"))
}


/**
 * Parse ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ into a Date object.
 * @param {string} date ASN.1 YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ date string.
 * @returns {Date} New date object
 */
utils.parseX509Date = function(date) {
    var match = /^([0-9]{2,4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/.exec(date)
    if (match === null) {
        return null
    }
    //- Where YY is less than 50, the year shall be interpreted as 20YY.
    const year = match[1].length === 2 && match[1] < 50 ? 2000 + parseInt(match[1]) : match[1]
    return new Date(Date.UTC(year, match[2]-1, match[3], match[4], match[5], match[6]))
}
