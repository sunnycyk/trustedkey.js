const httpUtils = module.exports = function(backendUrl, appId, appSecret) {
    this.backendUrl = backendUrl
    this.appId = appId
    this.appSecret = appSecret
}

const Querystring = require('querystring')
const RP          = require('request-promise-native')

const Utils       = require('../utils')


function getAuthHeader(url, appId, appSecret) {
    const payload = {
        typ: 'JWT',
        cty: 'JWT',
        iss: appId,
        aud: url
    }
    return 'Bearer ' + Utils.createHmacJws(payload, appSecret)
}


httpUtils.prototype.get = function(path, params) {
    const url = path + '?' + Querystring.stringify(params)
    const headers = {}
    if(this.appId && this.appSecret) {
        headers['Authorization'] = getAuthHeader(url, this.appId, this.appSecret)
    }

    return RP.get({
        baseUrl: this.backendUrl,
        uri: url,
        json: true,
        headers: headers
    })
}
