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
    const url = URL.parse(path, true)
    Object.assign(url.query, params)
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
 * @param {object} message - Message can be string or object. Objects will be JSON stringified
 * @param {String} secret - HMAC shared secret
 * @param {object} header - JOSE header
 * @returns {boolean}
 */
utils.verifyJws = function(jws, secretCallback) {

    const parts = jws.split(/\./g)
    if (parts.length !== 3) {       // JWE has 5 parts
        return false
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
        return false
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
        Assert.strictEqual(typeof jwk.d, "undefined")
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
        Assert.strictEqual(typeof jwk.d, "undefined")
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
    // Sign a digest value
    // Get the uncompressed public key without prefix, take the sha256 hash, and skip the first 12 bytes
    var blob = new Buffer(pubkeyhex.substr(2), 'hex')
    var digest = utils.sha256(blob, 'hex')
    return "0x" + digest.substr(2*12)
}


/**
 * Wrap the call and change the callback into a promise resolve or reject.
 */
utils.promisify = function(call) {
    return function() {
        // Save the 'this' reference for use inside the promise
        var self = this;
        var args = Array.prototype.slice.call(arguments);
        return new Promise( (resolve,reject) => {
            // Append the callback that either rejects or resolves the promise
            args.push( (err,a,b,c,d) => err?reject(err):resolve(a,b,c,d) );
            call.apply(self, args);
        })
    }
}


/**
 * Generate a 32-byte random nonce.
 * @param {String} encoding - Encoding for result (default base64)
 * @returns {String} The encoding of the nonce
 */
utils.generateNonce = function(encoding) {
    return Crypto.randomBytes(32).toString(encoding || 'base64')
}
