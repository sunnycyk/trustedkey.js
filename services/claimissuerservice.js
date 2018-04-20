const HttpUtils = require('./http')


// Error strings
const errPending = "The operation is pending."
const errFailed  = "failed"
const errJsonWithoutData = "Unexpected: IssuerApi.getClaims returned invalid data object."
const errInvalidPemArray = "Unexpected: IssuerApi.getClaims pemArray had < 2 elements."
const errInvalidPemData = "Unexpected: IssuerApi.getClaims PEM data was invalid."


/**
 * A base implementation of the issuer API. Specific issuer APIs will derive from this.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const ClaimIssuerService = module.exports = function(backendUrl, appId, appSecret) {
    this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}


/**
 * Get the claim(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString - The requestID that was provided during a prior call to the issuer-specific `requestClaims` API.
 * @returns {Promise<Array<String>>} - Promise containing PEM array
*/
ClaimIssuerService.prototype.getClaims = function(requestIdString) {
    return this.httpClient.get('getTokens', {
        requestid: requestIdString
    }).then(json => {
        if(!json.data) {
            throw new Error(errJsonWithoutData)
        }

        if(!json.data.result) {
            throw new Error(errPending)
        }

        if(!json.data.pems || json.data.pems.length === 0) {
            throw new Error(errInvalidPemData)
        }

        var pemArray = json.data.pems.replace(/-\r?\n-/g, '-\n!-').split('!')
        if(pemArray.length === 0) {
            throw new Error(errInvalidPemArray)
        }

        return pemArray
    })
}


/**
 * Request image claim(s).
 *
 * @param {Object} requestInfo - The requestInfo structure.
 * @returns {Promise} Promise returning true if success
*/
ClaimIssuerService.prototype.requestImageClaims = function(requestInfo) {
    return this.httpClient.post('requestImageTokens', {}, requestInfo).then(json => {
        if(!json.data) {
            throw new Error(errJsonWithoutData)
        }

        if(!json.data.requestImageTokens) {
            throw new Error(errFailed)
        }

        return true
    })
}


/**
 * Delete the claim(s) for the request identified by the given requestID.
 *
 * @param {String} requestIdString - The requestID that was provided during a prior call to the issuer-specific `requestClaims` API.
 * @throws {Error} Throws Error if request failed
 * @returns {Promise} Promise returning true if success
*/
ClaimIssuerService.prototype.deleteClaims = function(requestIdString) {
    return this.httpClient.get(this.backendUrl, 'deleteRequest', {
        requestid: requestIdString
    }).then(json => {
        if(!json.data) {
            throw new Error(errJsonWithoutData)
        }

        if(!json.data.result) {
            throw new Error(errFailed)
        }

        return true
    })
}


/**
 * Delete all the claims for the default credential.
 *
 * @throws {Error} Throws Error if request failed
 * @returns {Promise} Promise returning true if success
*/
ClaimIssuerService.prototype.deleteAllClaims = function() {
    return this.httpClient.get(this.backendUrl, 'deleteAllRequests').then(json => {
        if(!json.data) {
            throw new Error(errJsonWithoutData)
        }

        if(!json.data.result) {
            throw new Error(errFailed)
        }

        return true
    })
}
