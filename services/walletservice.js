const HttpUtils = require('./http')


// Common JSON sanity check callback
function checkSuccess(jsonData) {
    if(!jsonData.data) {
        throw new Error('API returned JSON without data')
    }

    return jsonData
}


/**
 * The API calls for implementing an identity credential/token wallet.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const WalletService = module.exports = function(backendUrl, appId, appSecret) {
    this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}


/**
 * Create a new pending request
 *
 * @param {String} address - Request address
 * @param {String} nonce - Request nonce
 * @param {String} callbackUrl - Callback URL
 * @param {String} documentUrl - Document URL
 * @param {String} objectIds - OIDs
 * @param {String?} message - OIDs
 * @param {String?} callbackType - OIDs
 * @param {number?} timeout - OIDs
 * @returns {Promise} JSON result from API
 */
WalletService.prototype.request = function(address, nonce, callbackUrl, documentUrl, objectIds, message, callbackType, timeout) {
    return this.httpClient.get('request', {
        address: address,
        nonce: nonce,
        callbackUrl: callbackUrl,
        documentUrl: documentUrl,
        objectIds: objectIds,
        message: message,
        callbackType: callbackType,
        timeout: timeout,
    }).then(checkSuccess)
}


/**
 * Grab the next login/signing request for the default registered credential.
 * @returns {Promise} JSON result from API
*/
WalletService.prototype.getPendingSignatureRequest = function() {
    return this.httpClient.get('getPendingRequest')
        .then(checkSuccess)
}


/**
 * Remove the pending request identified by its nonce.
 *
 * @param {String} nonceString - The unique nonce for the login request, as received from the notification or pending request.
 * @returns {Promise} JSON result from API
*/
WalletService.prototype.removeSignatureRequest = function(nonceString) {
    return this.httpClient.get('removePendingRequest', {
        nonce: nonceString
    }).then(checkSuccess)
}


/**
 * Register this device with the notification service. This enables the app to receive
 * remote notification for notification sent to the default registered credential.
 *
 * @param {String} deviceTokenString The device's token for receiving notifications
 * @returns {Promise} JSON result from API
*/
WalletService.prototype.registerDevice = function(deviceTokenString) {
    return this.httpClient.get('registerDevice', {
        devicetoken: deviceTokenString
    }).then(checkSuccess)
}


/**
 * Send notification to a device
 *
 * @param {String} address - Device to notify
 * @param {String} nonce - Request nonce
 * @param {String} message - Notification message
 * @returns {Promise} JSON result from API
 */
WalletService.prototype.notify = function(address, nonce, message) {
    return this.httpClient.get('notify', {
        address: address,
        nonce: nonce,
        message: message,
    }).then(checkSuccess)
}
