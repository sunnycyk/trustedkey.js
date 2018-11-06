const HttpUtils = require('./http')
const Crypto = require('crypto')
const Assert = require('assert')

module.exports = CredentialRegistryService

/**
 * Utility class with wrappers for the various Credential Registry API endpoints.
 *
 * @constructor
 * @param {String} backendUrl The base backend URL
 * @param {String} [appId] Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] Application shared secret, without this only unauthorized APIs can be used
 */
function CredentialRegistryService (backendUrl, appId, appSecret) {
  this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}

/**
 * Revoke our default credential by sending a request to the blockchain. The receiver must have been registered as
 * a delegate in the smart contract. A challenge is signed by the default registered credential, which is
 * verified by the smart contract.
 *
 * @param {string} delegateAddressString The hex-encoded blockchain address of the registered delegate credential.
 * @param {Object} keyPair Jsrsasign keypair object
 * @param {string} [address] When revoking a claim, its address
 * @returns {Promise.<object>} returning JSON from API
 */
CredentialRegistryService.prototype.revokeCredential = function (delegateAddressString, keyPair, address) {
  Assert.strictEqual(typeof delegateAddressString, 'string', 'delegateAddressString must be of type `string`')
  Assert.strictEqual(typeof keyPair, 'object', 'keyPair must be of type `object`')
  Assert.strictEqual(0 in keyPair, false, 'keyPair should not be Buffer or Array-like')

  const addressWithout0x = delegateAddressString.replace('0x', '')
  var hash = Crypto.createHash('sha256')
  var digest = hash.update(addressWithout0x, 'hex').update(address ? 'indirect' : 'revocation').digest('hex')
  var sig = keyPair.signWithMessageHash(digest)

  return this.httpClient.get('revoke', {
    signature: sig,
    pubkey: keyPair.pubKeyHex,
    address: address
  })
}

/**
 * Revoke claim by sending a request to the blockchain.  The receiver must have been registered as
 * a delegate in the smart contract.
 *
 * @param {string} address When revoking a cliam, its address
 * @returns {Promise.<object>} return JSON from API
 */
CredentialRegistryService.prototype.revokeClaim = function (address) {
  Assert.strictEqual(typeof address, 'string', 'address must be of type `string`')

  return this.httpClient.get('revoke', {
    address: address
  })
}
