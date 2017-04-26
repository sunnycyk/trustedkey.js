const HttpUtils = require('./http')


/**
 * A base implementation of the issuer API. Specific issuer APIs will derive from this.
 *
 * @constructor
 */
const TokenIssuerService = module.exports = function(backendUrl) {
    this.backendUrl = backendUrl
}


/**
 * Get the token(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString - The requestID that was provided during a prior call to the issuer-specific `requestTokens` API.
*/
TokenIssuerService.prototype.getTokens = function(requestIdString) {
    return HttpUtils.get(this.backendUrl, 'getCertificates', {
        requestid: requestIdString
    })
}


/**
 * Delete the token(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString - The requestID that was provided during a prior call to the issuer-specific `requestTokens` API.
*/
TokenIssuerService.prototype.deleteTokens = function(requestIdString) {
    return HttpUtils.get(this.backendUrl, 'getCertificates', {
        requestid: requestIdString
    })
}


/**
 * Delete all the tokens for the default credential.
*/
TokenIssuerService.prototype.deleteAllTokens = function() {
    return HttpUtils.get(this.backendUrl, 'getCertificates')
}
