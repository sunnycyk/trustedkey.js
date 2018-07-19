const ClaimIssuerService = require('./claimissuerservice.js')

module.exports = TrustedKeyIssuerService

/**
 * Trusted Key issuer API implementation
 *
 * @constructor
 * @augments {ClaimIssuerService}
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
function TrustedKeyIssuerService (backendUrl, appId, appSecret) {
  ClaimIssuerService.call(this, backendUrl, appId, appSecret)
}
TrustedKeyIssuerService.prototype = Object.create(ClaimIssuerService.prototype)

/**
 * Request mock claims, for testing during development only. See `requestClaims`.
 * @param {string} requestIdString: A unique ID for this request (for example, an UUID) for retries and notifications.
 * @returns {Promise.<Object>} JSON result from API
*/
TrustedKeyIssuerService.prototype.requestMockClaims = function (requestIdString) {
  return this.httpClient.get('registerIdentity', {
    requestid: requestIdString
  })
}

/**
 * Request claims for the credentials with the Trusted Key Demo Issuer. The Trusted Key Demo Issuer
 * uses AuthenticID as the source of the personal information and as such requires the
 * caller to provide a valid AuthenticID transaction ID. This is usually obtained by a
 * previous call to the AuthenticID REST API.
 *
 * Upon success, the request has been accepted and the app will be notified when done.
 * Upon failure, the request can be retried by providing the same requestID.
 *
 * @param {string} requestIdString: A unique ID for this request (for example, an UUID) for retries and notifications.
 * @param {string} catfishAirTransactionIDString: A transaction ID, obtained from the AuthenticID REST API.
 * @param {string} [catfishAirVersionNumber]: The version of the CatfishAIR REST API to use.
 * @returns {Promise.<Object>} JSON result from API
*/
TrustedKeyIssuerService.prototype.requestAuthenticIDClaims = function (requestIdString, catfishAirTransactionIDString, catfishAirVersionNumber) {
  return this.httpClient.get('registerAuthenticId', {
    transactionid: catfishAirTransactionIDString,
    version: catfishAirVersionNumber,
    requestid: requestIdString
  })
}
