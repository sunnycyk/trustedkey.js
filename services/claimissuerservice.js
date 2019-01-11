const HttpUtils = require('./http')

// Error strings
const errPending = 'The operation is pending.'
const errFailed = 'failed'
const errJsonWithoutData = 'Unexpected: IssuerApi.getClaims returned invalid data object.'
const errInvalidPemArray = 'Unexpected: IssuerApi.getClaims pemArray had < 2 elements.'
const errInvalidPemData = 'Unexpected: IssuerApi.getClaims PEM data was invalid.'

module.exports = ClaimIssuerService
/**
 * A base implementation of the issuer API. Specific issuer APIs will derive from this.
 *
 * @constructor
 * @param {String} backendUrl The base backend URL
 * @param {String} [appId] Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] Application shared secret, without this only unauthorized APIs can be used
 */
function ClaimIssuerService (backendUrl, appId, appSecret) {
  this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}

/**
 * Get the claim(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString The requestID that was provided during a prior call to the issuer-specific `requestClaims` API.
 * @param {String} [pubkey] Only issuer needs to provide user's public key to get the claim
 * @returns {Promise.<Array.<String>>} Promise containing PEM array
*/
ClaimIssuerService.prototype.getClaims = function (requestIdString, pubkey) {
  return this.httpClient.get('getTokens', {
    requestid: requestIdString,
    pubkey: pubkey
  }).then(json => {
    if (!json.data) {
      throw new Error(errJsonWithoutData)
    }

    if (!json.data.result) {
      throw new Error(errPending)
    }

    if (!json.data.pem || json.data.pem.length === 0) {
      throw new Error(errInvalidPemData)
    }

    var pemArray = json.data.pem.replace(/-\r?\n-/g, '-\n!-').split('!')
    if (pemArray.length === 0) {
      throw new Error(errInvalidPemArray)
    }

    return pemArray
  })
}

/**
 * @typedef {string|{data:string,loa:number=}} AttributeValue
 *
 * @typedef ImageInfo
 * @type {object}
 * @property {string} name A unique file name for this image.
 * @property {string} data The base64 encoded image data.
 * @property {Dotted} [oid] An optional OID for this image.
 * @property {number} [loa] An optional level of assurance.
 *
 * @typedef RequestInfo
 * @type {object}
 * @property {string} pubkey The HEX-encoded ES256 public key of the subject.
 * @property {string} expiry The expiry date and time for the issued claims.
 * @property {Object.<Dotted,AttributeValue>} attributes A map with `"OID":"value"` pairs.
 * @property {string} [requestid] A unique ID for this request (for example, an UUID) for retries and notifications.
 * @property {Array.<ImageInfo>} [images] An array with images, each with a `ImageInfo` map.
*/

/**
 * Request claims with the specified attributes and optional document images.
 *
 * @param {RequestInfo} requestInfo The RequestInfo structure.
 * @returns {Promise.<boolean>} Promise returning true if success
*/
ClaimIssuerService.prototype.requestImageClaims = function (requestInfo) {
  return this.httpClient.post('requestImageTokens', {}, requestInfo).then(json => {
    if (!json.data) {
      throw new Error(errJsonWithoutData)
    }

    if (!json.data.requestImageTokens) {
      throw new Error(errFailed)
    }

    return true
  })
}

/**
 * Delete the claim(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString The requestID that was provided during a prior call to the issuer-specific `requestClaims` API.
 * @throws {Error} Throws Error if request failed
 * @returns {Promise.<boolean>} Promise returning true if success
*/
ClaimIssuerService.prototype.deleteClaims = function (requestIdString) {
  return this.httpClient.get(this.backendUrl, 'deleteRequest', {
    requestid: requestIdString
  }).then(json => {
    if (!json.data) {
      throw new Error(errJsonWithoutData)
    }

    if (!json.data.result) {
      throw new Error(errFailed)
    }

    return true
  })
}

/**
 * Delete all the claims for the default credential.
 *
 * @throws {Error} Throws Error if request failed
 * @returns {Promise.<boolean>} Promise returning true if success
*/
ClaimIssuerService.prototype.deleteAllClaims = function () {
  return this.httpClient.get(this.backendUrl, 'deleteAllRequests').then(json => {
    if (!json.data) {
      throw new Error(errJsonWithoutData)
    }

    if (!json.data.result) {
      throw new Error(errFailed)
    }

    return true
  })
}
