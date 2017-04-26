const httpUtils = module.exports = {}

const Querystring = require('querystring')
const Crypto      = require('crypto')
const RP          = require('request-promise-native')


httpUtils.get = function(baseUrl, path, params) {
    const url = path + '?' + Querystring.stringify(params)

    return RP.get({
        baseUrl: baseUrl,
        uri: url,
        json: true
    })
}


httpUtils.getSigned = function(baseUrl, path, params, keyPair) {
    const url = path + '?' + Querystring.stringify(params)

    // Sign a digest value
    var hash = Crypto.createHash('sha256')
    var digest = hash.update(url).digest('hex')
    var sig = keyPair.signWithMessageHash(digest)

    return RP.get({
        baseUrl: baseUrl,
        uri: url,
        json: true,
        headers: {'Authorization': 'secp256r1 '+ keyPair.pubKeyHex +':'+sig }
    })
}
