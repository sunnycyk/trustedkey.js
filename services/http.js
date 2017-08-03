const RP          = require('request-promise-native')

const Utils       = require('../utils')


const httpUtils = module.exports = function(backendUrl, appId, appSecret) {
    this.backendUrl = backendUrl
    this.appId = appId
    this.appSecret = appSecret
}


function getAuthHeader(url, appId, appSecret) {
    const payload = {
        iss: appId,
        aud: url,
        exp: Utils.getUnixTime()+300
    }
    const header = {typ: 'JWT', iss: appId }
    return 'Bearer ' + Utils.createHmacJws(payload, appSecret, header)
}


httpUtils.prototype.get = function(path, params) {

    const url = Utils.mergeQueryParams(path, params||null)
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


httpUtils.prototype.post = function(path, params) {

    const url = Utils.mergeQueryParams(path, params||null)
    const headers = {}
    if(this.appId && this.appSecret) {
        headers['Authorization'] = getAuthHeader(this.backendUrl + url, this.appId, this.appSecret)
    }

    return RP.post({
        baseUrl: this.backendUrl,
        uri: url,
        json: true,
        headers: headers
    })
}
