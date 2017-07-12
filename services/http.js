const RP          = require('request-promise-native')
const URL         = require('url')

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


function mergeParams(path, params) {
    const url = URL.parse(path, true)
    Object.assign(url.query, params)
    delete url.search   // force recreation from .query
    return  url.format()
}


httpUtils.prototype.get = function(path, params) {

    const url = mergeParams(path, params)
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

    const url = mergeParams(path, params)
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
