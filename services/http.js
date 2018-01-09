const RP          = require('request-promise-native')
const Assert      = require('assert')
const URL         = require('url')

const Utils       = require('../utils')


/**
 * Utility class with wrappers for calling authenticated API endpoints.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const httpUtils = module.exports = function(backendUrl, appId, appSecret) {

    Assert.strictEqual(typeof backendUrl, "string", 'backendUrl must be of type `string`')
    // Assert.strictEqual(typeof appId, "string", 'appId must be of type `string`')
    // Assert.strictEqual(typeof appSecret, "string", 'appSecret must be of type `string`')

    this.backendUrl = backendUrl
    this.appId = appId
    this.appSecret = appSecret
}


function getAuthHeader(url, appId, appSecret, body) {
    const iat = Utils.getUnixTime()
    const payload = {
        iss: appId,
        aud: url,
        iat: iat,
        exp: iat + 300,
        body: body ? Utils.sha256(body, 'hex') : null,
    }
    const header = {typ: 'JWT', iss: appId }
    return 'Bearer ' + Utils.createHmacJws(payload, appSecret, header)
}


httpUtils.prototype.getHeaders = function(absoluteUrl, body) {

    if (this.appId && this.appSecret) {
        return {Authorization: getAuthHeader(absoluteUrl, this.appId, this.appSecret, body)}
    }
    else {
        return {}
    }
}


httpUtils.prototype.get = function(path, params) {

    const url = Utils.mergeQueryParams(path, params||{})
    const absoluteUrl = URL.resolve(this.backendUrl, url)
    return RP.get({
        uri: absoluteUrl,
        json: true,
        headers: this.getHeaders(absoluteUrl)
    })
}


httpUtils.prototype.post = function(path, params, jsonBody) {

    const url = Utils.mergeQueryParams(path, params||{})
    const absoluteUrl = URL.resolve(this.backendUrl, url)
    // Assume RP does the exact same serialization of the body
    const body = jsonBody === undefined ? "" : JSON.stringify(jsonBody)
    return RP.post({
        uri: absoluteUrl,
        json: true,
        headers: this.getHeaders(absoluteUrl, body),
        body: jsonBody
    })
}
