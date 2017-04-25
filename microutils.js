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
const Jsrsasign = require('jsrsasign')

const micro = module.exports = {}
micro.shortcuts = {}

// CONSIDER: store client keypair in config
const clientKeyPair = Jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1").prvKeyObj

// CONSIDER: caller should provide absolute URLs
const BaseUrl = 'https://demo.trustedkey.com/'


micro.shortcuts.checkRevocation = function(subjectaddress) {

    if (typeof subjectaddress === 'object') {
        subjectaddress = subjectaddress.join(',')
    }

    return micro.get('isRevoked', {
        address: subjectaddress
    }).then(r => {
        if (r.data.isRevoked !== false) {
            throw new Errors.ApplicationError("Address got revoked: "+subjectaddress)
        }
        return true
    })
}


micro.shortcuts.notify = function(address, nonce, message) {

    return micro.getSigned('notify', {
        address: address,
        nonce: nonce,
        message: message,
    }, clientKeyPair)
}


micro.shortcuts.request = function(address, nonce, callbackUrl, documentUrl, objectIds) {

    return micro.getSigned('request', {
        address: address,
        nonce: nonce,
        callbackUrl: callbackUrl,
        documentUrl: documentUrl,
        objectIds: objectIds,
    }, clientKeyPair)
}


micro.get = function(path, params){

    const url = path + '?' + Querystring.stringify(params)

    return RP.get({
        baseUrl: BaseUrl,
        uri: url,
        json: true
    })
}


micro.getSigned = function(path, params, keyPair) {

    const url = path + '?' + Querystring.stringify(params)

    // Sign a digest value
    var hash = Crypto.createHash('sha256')
    var digest = hash.update(url).digest('hex')
    var sig = keyPair.signWithMessageHash(digest)

    return RP.get({
        baseUrl: BaseUrl,
        uri: url,
        json: true,
        headers: {'Authorization': 'secp256r1 '+keyPair.pubKeyHex+':'+sig }
    })
}
