const TokenIssuerService = require('./tokenissuerservice.js')
const HttpUtils = require('./http')


/**
 * Trusted Key issuer API implementation
 *
 * @constructor
 */
const TrustedKeyIssuerService = module.exports = function(backendUrl, appKeyPair) {
    TokenIssuerService.call(this, backendUrl, appKeyPair)
}
TrustedKeyIssuerService.prototype = Object.create(TokenIssuerService.prototype)


/**
 * Request mock tokens, for testing during development only. See `requestTokens`.
*/
TrustedKeyIssuerService.prototype.requestMockTokens = function(requestIdString) {
    return HttpUtils.get(this.backendUrl, 'registerIdentity', {
        requestid: requestIdString
    })
}


/**
 * Request tokens for the credentials with the Trusted Key Demo Issuer. The Trusted Key Demo Issuer
 * uses AuthenticID as the source of the personal information and as such requires the
 * caller to provide a valid AuthenticID transaction ID. This is usually obtained by a
 * previous call to the AuthenticID REST API.
 *
 * Upon success, the request has been accepted and the app will be notified when done.
 * Upon failure, the request can be retried by providing the same requestID.
 *
 * @param requestIdString: A unique ID for this request (for example, an UUID) for retries and notifications.
 * @param catfishAirTransactionIDString: A transaction ID, obtained from the AuthenticID REST API.
 * @param catfishAirVersionNumber: The version of the CatfishAIR REST API to use.
*/
TrustedKeyIssuerService.prototype.requestTokens = function(requestIDString, catfishAirTransactionIDString, catfishAirVersionNumber) {
    return HttpUtils.get(this.backendUrl, 'registerAuthenticId', {
        transactionid: catfishAirTransactionIDString,
        version: catfishAirVersionNumber,
        requestid: requestIDString
    })
}
