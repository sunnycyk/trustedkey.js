//
//  utils.js
//
//  Copyright © 2016 Trusted Key Solutions. All rights reserved.
//

const Crypto    = require('crypto')
const Jsrsasign = require('jsrsasign')

const utils = module.exports = {}


utils.serialToAddress = function(serialhex) {
    const paddedSerial = String('00000000000000000000000000000000000000'+serialhex).slice(-40)
    return "0x" + paddedSerial
}


utils.base64url = function(a) {
    return Buffer.from(a).toString("base64").replace(/=/g,'').replace(/\//g,'_').replace(/\+/g,'-')
}


utils.getUnixTime = function(date) {
    return Math.floor((date||new Date).getTime()/1000)
}


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


utils.verifyJws = function(jws, secretCallback) {

    const parts = jws.split(/\./g)
    if (parts.length !== 3) {       // JWE has 5 parts
        return false
    }

    const jose = JSON.parse(Buffer.from(parts[0], "base64"))
    const message = Buffer.from(parts[1], "base64")
    const signature = Buffer.from(parts[2], "base64")
    const signeddata = parts[0] + '.' + parts[1]

    if (jose.alg === 'ES256') {
        // ECDSA-SHA256
        const claims = JSON.parse(message)
        // Subject public key is stored in 'sub' claim
        if (utils.checkECDSA("secp256r1", signeddata, secretCallback(claims), signature.toString('hex'))) {
            return claims
        }
        return false
    }
    else if (jose.alg === 'HS256') {
        // HMAC-SHA256
        const hmac = Crypto.createHmac('sha256', secretCallback(jose))
        if (hmac.update(signeddata).digest().equals(signature)) {
            // Verify any nested JWT
            if (jose.cty === "JWT") {
                return utils.verifyJws(message.toString(), secretCallback)
            }
            else {
                return message
            }
        }
    }

    return false
}


utils.checkECDSA = function(curveName, message, pubkey, signature) {

    // Verify a digest value
    var hash = Crypto.createHash('sha256')
    var digest = hash.update(message).digest().toString('hex')

    var curve = new Jsrsasign.KJUR.crypto.ECDSA({xy:pubkey,curve:curveName})
    return curve.verifyHex(digest, signature, pubkey)
}


utils.userPubKeyHexToAddress = function(pubkeyhex) {
    // Sign a digest value
    var hash = Crypto.createHash('sha256')
    // Get the uncompressed public key without prefix, take the sha256 hash, and skip the first 12 bytes
    var blob = new Buffer(pubkeyhex.substr(2), 'hex')
    var digest = hash.update(blob).digest()
    return "0x" + digest.toString('hex').substr(2*12)
}
