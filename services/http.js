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
        iss: appId,
        aud: url,
    }
    const header = {typ: 'JWT', iss: appId}
    return 'Bearer ' + Utils.createHmacJws(payload, appSecret, header)
}


httpUtils.prototype.get = function(path, params) {
    const url = path + '?' + Querystring.stringify(params)
    const headers = {}
    if(this.appId && this.appSecret) {
        headers['Authorization'] = getAuthHeader(this.backendUrl + url, this.appId, this.appSecret)
    }

    return RP.get({
        baseUrl: this.backendUrl,
        uri: url,
        json: true,
        headers: headers
    })
}
