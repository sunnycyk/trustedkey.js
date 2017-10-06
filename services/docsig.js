const Utils      = require('../utils')
const HttpUtils = require('./http')

/**
 * Submit
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} appId - Wallet application ID
 * @param {String} appSecret - Wallet shared secret
 *
 * @param {String} docsigAppId - Docsig application ID
 * @param {String} docsigAppSecret - Docsig shared secret
 */
const DocsigService = module.exports = function(backendUrl, appId, appSecret, docsigAppId, docsigAppSecret) {
    this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
    this._docsigAppId = docsigAppId
    this._docsigAppSecret = docsigAppSecret
}


/**
 * Submit a document to be signed
 *
 * @param {String} signatoryEmail - Signatory email address
 * @param {String} callbackUrl - Url where signed PDF will be uploaded with PUT
 * @param {String} documentUrl - Url where document can be downloaded
 * @param {String} objectIds - Array of objectIds to request from signatory
 * @returns {String} JSON response from API
 */
DocsigService.prototype.documentSignRequest = function(signatoryEmail, callbackUrl, documentUrl, objectIds) {
    const appId = this._docsigAppId
    const appSecret = this._docsigAppSecret

    const payload = {
        iss: appId,
        signatory: signatoryEmail,
        callbackUrl: callbackUrl,
        documentUrl: documentUrl,
        objectIds: objectIds
    }
    const header = {typ: 'JWT', iss: appId}
    const jwt = Utils.createHmacJws(payload, appSecret, header)

    return this.httpClient.post('newDocumentSignRequest?jwt=' + jwt)
}
