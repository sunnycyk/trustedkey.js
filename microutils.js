//
//  microutils.js
//
//  Utilities to access internal services
//
//  Copyright © 2017 Trusted Key Solutions. All rights reserved.
//

const RP          = require('request-promise-native')
const Crypto      = require('crypto')
const Errors      = require('./errors')
const Querystring = require('querystring')
const Jsrsasign   = require('jsrsasign')

const micro = module.exports = function(baseUrl, clientKeyPair) {
    this.baseUrl = baseUrl || 'https://demo.trustedkey.com/'
    this.clientKeyPair = clientKeyPair || Jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1").prvKeyObj

    this.clientKeyPair = clientKeyPair

    this.shortcuts = new shortcuts(this)
}

function shortcuts(microInstance) {
    this.micro = microInstance
}


shortcuts.prototype.checkRevocation = function(subjectaddress) {

    if (typeof subjectaddress === 'object') {
        subjectaddress = subjectaddress.join(',')
    }

    return this.micro.get('isRevoked', {
        address: subjectaddress
    }).then(r => {
        if (r.data.isRevoked !== false) {
            throw new Errors.ApplicationError("Address got revoked: "+subjectaddress)
        }
        return true
    })
}


shortcuts.prototype.notify = function(address, nonce, message) {

    return this.micro.getSigned('notify', {
        address: address,
        nonce: nonce,
        message: message,
    }, this.micro.clientKeyPair)
}


shortcuts.prototype.request = function(address, nonce, callbackUrl, documentUrl, objectIds) {

    return this.micro.getSigned('request', {
        address: address,
        nonce: nonce,
        callbackUrl: callbackUrl,
        documentUrl: documentUrl,
        objectIds: objectIds,
    }, this.micro.clientKeyPair)
}


micro.prototype.get = function(path, params){

    const url = path + '?' + Querystring.stringify(params)

    return RP.get({
        baseUrl: this.baseUrl,
        uri: url,
        json: true
    })
}


micro.prototype.getSigned = function(path, params, keyPair) {

    const url = path + '?' + Querystring.stringify(params)

    // Sign a digest value
    var hash = Crypto.createHash('sha256')
    var digest = hash.update(url).digest('hex')
    var sig = keyPair.signWithMessageHash(digest)

    return RP.get({
        baseUrl: this.baseUrl,
        uri: url,
        json: true,
        headers: {'Authorization': 'secp256r1 '+keyPair.pubKeyHex+':'+sig }
    })
}
