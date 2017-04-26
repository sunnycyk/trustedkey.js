const HttpUtils = require('./http')


/**
 * The API calls for implementing an identity credential/token wallet.
 * @constructor
 */
const WalletService = module.exports = function(backendUrl) {
    this.backendUrl = backendUrl
}

/**
 * Grab the next login/signing request for the default registered credential.
 *
 * @returns {[Promise, JSON]}
*/
WalletService.prototype.getPendingSignatureRequest = function() {
    return HttpUtils.get(this.backendUrl, 'getPendingRequest')
}


/**
 * Remove the pending request identified by its nonce.
 *
 * @param {String} nonceString - The unique nonce for the login request, as received from the notification or pending request.
*/
WalletService.prototype.removeSignatureRequest = function(nonceString) {
    return HttpUtils.get(this.backendUrl, 'removePendingRequest', {
        nonce: nonceString
    })
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
    })
}
