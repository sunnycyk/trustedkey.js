const HttpUtils = require('./http')


// Common JSON sanity check callback
function checkSuccess(jsonData) {
    if(!jsonData.data) {
        throw new Error('API returned JSON without data')
    }

    if(!jsonData.data.result) {
        throw new Error('Api returned result "false"')
    }

    return jsonData
}


/**
 * The API calls for implementing an identity credential/token wallet.
 * @constructor
 */
const WalletService = module.exports = function(backendUrl, appKeyPair) {
    this.appKeyPair = appKeyPair
    this.backendUrl = backendUrl
}

/**
 * Create a new pending request
 *
 * @param {String} address - Request address
 * @param {String} nonce - Request nonce
 * @param {String} callbackUrl - Callback URL
 * @param {String} documentUrl - Document URL
 * @param {String} objectIds - OIDs
 */
WalletService.prototype.request = function(address, nonce, callbackUrl, documentUrl, objectIds) {
    return HttpUtils.getSigned(this.baseUrl, 'request', {
        address: address,
        nonce: nonce,
        callbackUrl: callbackUrl,
        documentUrl: documentUrl,
        objectIds: objectIds,
    }, this.appKeyPair).then(checkSuccess)
}

/**
 * Grab the next login/signing request for the default registered credential.
*/
WalletService.prototype.getPendingSignatureRequest = function() {
    return HttpUtils.get(this.backendUrl, 'getPendingRequest').then(checkSuccess)
}


/**
 * Remove the pending request identified by its nonce.
 *
 * @param {String} nonceString - The unique nonce for the login request, as received from the notification or pending request.
*/
WalletService.prototype.removeSignatureRequest = function(nonceString) {
    return HttpUtils.get(this.backendUrl, 'removePendingRequest', {
        nonce: nonceString
    }).then(checkSuccess)
}

/**
 * Register this device with the notification service. This enables the app to receive
 * remote notification for notification sent to the default registered credential.
 *
 * @param {String} deviceTokenString
*/
WalletService.prototype.registerDevice = function(deviceTokenString) {
    return HttpUtils.get(this.backendUrl, 'registerDevice', {
        devicetoken: deviceTokenString
    }).then(checkSuccess)
}


/**
 * Send notification to a device
 *
 * @param {String} address - Device to notify
 * @param {String} nonce -
 */
WalletService.prototype.notify = function(address, nonce, message) {
    return HttpUtils.getSigned(this.baseUrl, 'notify', {
        address: address,
        nonce: nonce,
        message: message,
    }, this.appKeyPair).then(checkSuccess)
}
