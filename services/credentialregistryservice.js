const HttpUtils = require('./http')
const Crypto    = require('crypto')

/**
 * Utility class with wrappers for the various Credential Registry API endpoints.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const CredentialRegistryService = module.exports = function(backendUrl, appId, appSecret) {
    this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}


/**
 * Revoke our default credential by sending a request to the blockchain. The receiver must have been registered as
 * a delegate in the smart contract. A challenge is signed by the default registered credential, which is
 * verified by the smart contract.
 *
 * @param delegateAddress: The hex-encoded blockchain address of the registered delegate credential.
 */
CredentialRegistryService.revokeDefaultCredential = function(delegateAddressString, keyPair) {
    var addressWithout0x = delegateAddressString.replace('0x', '')

    var hash = Crypto.createHash('sha256')
    var digest = hash.update(addressWithout0x).digest('hex')
    var sig = keyPair.signWithMessageHash(digest)

    return this.httpClient.get('revoke', {
        signature: sig.digest('hex')
    })
}
