const HttpUtils = require('./http')
const RP = require('request-promise-native')

module.exports = WalletService

// Common JSON sanity check callback
function checkSuccess (jsonData) {
  if (!jsonData.data) {
    throw Error('API returned JSON without data')
  }

  return jsonData
}

/**
 * The API calls for implementing an identity claim/credential wallet.
 *
 * @constructor
 * @param {String} backendUrl The base backend URL
 * @param {String} [appId] Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] Application shared secret, without this only unauthorized APIs can be used
 */
function WalletService (backendUrl, appId, appSecret) {
  this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}

/**
 * @typedef ClaimOptions
 * @type {object}
 *
 * @typedef {{userInfo: Object.<string,ClaimOptions?>}} ClaimsOptions
 *
 * @typedef AuthorizeOptions
 * @type {object}
 * @property {string} [scope] space delimited OpenID-Connect scopes; defaults to `openid`
 * @property {string} [response_type] the authorization processing flow to be used; defaults to 'code'
 * @property {string} [response_mode] the mechanism to be used for returning parameters
 * @property {string} [nonce] string value used to associate a Client session with an ID Token
 * @property {string} [display] specifies how to displays the user interface pages
 * @property {string} [prompt] space delimited values that specifies whether to prompt for reauthentication
 * @property {string} [login_hint] the login identifier the End-User might use to log in
 * @property {ClaimsOptions|string} [claims] JSON with the specific Claims be returned
 */

/**
 * Create a new OAuth/OpenID-Connect authorization request
 *
 * @param {String} redirectUri Redirection URI to which the response will be sent
 * @param {String} state Opaque value used to maintain state between the request and the callback
 * @param {AuthorizeOptions} [options] Additional authorization options
 * @returns {String} URL for OAuth/OpenID-Connect authorization request
 */
WalletService.prototype.buildAuthorizeUrl = function (redirectUri, state, options) {
  const required = {
    client_id: this.httpClient.appId,
    redirect_uri: redirectUri,
    state: state,
    response_type: 'code',
    scope: 'openid'
  }
  if (options && options.claims instanceof Object) {
    options.claims = JSON.stringify(options.claims)
  }
  return this.httpClient.buildUrl('/oauth/authorize', Object.assign(required, options || {}))
}

/**
 * Get an OAuth access_token from an OAuth authorization code
 *
 * @param {String} redirectUri Redirection URI to which the response will be sent
 * @param {String} code the authorization code received from `/authorize`
 * @returns {Promise.<object>} JSON result from API
 */
WalletService.prototype.token = function (redirectUri, code) {
  const required = {
    client_id: this.httpClient.appId,
    client_secret: this.httpClient.appSecret,
    redirect_uri: redirectUri,
    code: code,
    grant_type: 'authorization_code'
  }
  const url = this.httpClient.buildUrl('/oauth/token')
  return RP.post(url, {
    json: true,
    form: required,
    forever: true
  })
}

/**
 * Get a user-information object associated with an access token
 *
 * @param {String} accessToken Access Token received from `/token`
 * @returns {Promise.<object>} JSON result from API
 */
WalletService.prototype.userInfo = function (accessToken) {
  const url = this.httpClient.buildUrl('/oauth/user')
  return RP.get(url, {
    headers: {authorization: 'Bearer ' + accessToken},
    json: true,
    forever: true
  })
}

/**
 * Grab the next login/signing request for the default registered credential.
 * @returns {Promise.<object>} JSON result from API
*/
WalletService.prototype.getPendingSignatureRequest = function () {
  return this.httpClient.get('getPendingRequest')
    .then(checkSuccess)
}

/**
 * Remove the pending request identified by its nonce.
 *
 * @param {String} nonceString The unique nonce for the login request, as received from the notification or pending request.
 * @returns {Promise.<object>} JSON result from API
*/
WalletService.prototype.removeSignatureRequest = function (nonceString) {
  return this.httpClient.delete('removePendingRequest', {
    nonce: nonceString
  }).then(checkSuccess)
}

/**
 * Register this device with the notification service. This enables the app to receive
 * remote notification for notification sent to the default registered credential.
 *
 * @param {String} deviceTokenString The device's token for receiving notifications
 * @returns {Promise.<object>} JSON result from API
*/
WalletService.prototype.registerDevice = function (deviceTokenString) {
  return this.httpClient.post('registerDevice', {
    devicetoken: deviceTokenString
  }).then(checkSuccess)
}

/**
 * Send notification to a device
 *
 * @param {String} address Device to notify
 * @param {String} nonce Request nonce
 * @param {String} message Notification message
 * @param {String} [walletId] Wallet-ID of the receiving Wallet App
 * @returns {Promise.<object>} JSON result from API
 */
WalletService.prototype.notify = function (address, nonce, message, walletId) {
  return this.httpClient.get('notify', {
    address: address,
    nonce: nonce,
    message: message,
    walletId: walletId
  }).then(checkSuccess)
}

/**
 * @typedef RequestOptions
 * @type {object}
 * @property {string} [username] Username of the account trying to log in (if known)
 * @property {string} [documentUrl] The URL to a document for PDF signing
 * @property {string|Array.<Dotted>} [objectIds] A comma-separated list of OIDs
 * @property {string} [message] An optional text message for transaction authorization
 * @property {string} [callbackType] The type of callback, one of "POST", "SYSTEM", or "JSON"
 * @property {number|string} [timeout] The timeout for the request in minutes
 */

/**
 * Send signature request to a device
 *
 * @param {string} address Device or user to notify
 * @param {string} nonce Request nonce
 * @param {string} callbackUrl Callback URL
 * @param {RequestOptions} [options] Optional request options
 * @returns {Promise.<object>} JSON result from API
 */
WalletService.prototype.request = function (address, nonce, callbackUrl, options) {
  const required = {
    address: address,
    nonce: nonce,
    callbackUrl: callbackUrl
  }
  if (options && options.objectIds instanceof Array) {
    // Convert Array to comma-separated string
    options = Object.assign({}, options, {objectIds: options.objectIds.join()})
  }
  return this.httpClient.get('request', Object.assign(required, options || {})).then(checkSuccess)
}

/**
 * Manual registration of an issued login name for the current credential.
 *
 * @param {String} identifier A unique login identifier for this user (for example, phone number.)
 * @param {String} claim A claim issued to the user credential, proving ownership of the identifier.
 * @returns {Promise.<object>} JSON result from API
*/
WalletService.prototype.registerLogin = function (identifier, claim) {
  return this.httpClient.post('registerLogin', {}, {
    identifier,
    claim
  }).then(checkSuccess)
}
