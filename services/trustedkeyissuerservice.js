const TokenIssuerService = require('./tokenissuerservice.js')


/**
 * Trusted Key issuer API implementation
 *
 * @constructor
 * @augments {TokenIssuerService}
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const TrustedKeyIssuerService = module.exports = function(backendUrl, appId, appSecret) {
    TokenIssuerService.call(this, backendUrl, appId, appSecret)
}
TrustedKeyIssuerService.prototype = Object.create(TokenIssuerService.prototype)


/**
 * Request mock tokens, for testing during development only. See `requestTokens`.
*/
TrustedKeyIssuerService.prototype.requestMockTokens = function(requestIdString) {
    return this.httpClient.get('registerIdentity', {
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
    return this.httpClient.get('registerAuthenticId', {
        transactionid: catfishAirTransactionIDString,
        version: catfishAirVersionNumber,
        requestid: requestIDString
    })
}
