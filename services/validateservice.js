const Assert = require('assert')
const Utils = require('../utils')
const RP = require('request-promise-native')

module.exports = ValidateService

/**
 * An implementation of a the validation API, used to check to validity of credentials and claims.
 *
 * @constructor
 * @param {String} backendUrl The base backend URL
 */
function ValidateService (backendUrl = 'https://issuer.trustedkey.com') {
  this.httpClient = {
    get: function (url, params) {
      const uri = Utils.mergeQueryParams(url, params || {})
      return RP({baseUrl: backendUrl, url: uri, json: true, forever: true})
    }
  }
}

function validate (httpClient, address) {
  Assert.strictEqual(typeof address, 'string', 'address must be of type `string`')

  return httpClient.get('isRevoked', {
    address: address
  }).then(r => {
    return !r.data.isRevoked
  })
}

/**
 * Check the status of the specified blockchain transaction ID.
 *
 * @param {String} txid Transaction ID to check.
 * @returns {Promise.<string>} Transaction status
*/
ValidateService.prototype.getTransactionStatus = function (txid) {
  Assert.strictEqual(typeof txid, 'string', 'txid must be of type `string`')

  return this.httpClient.get('getTransactionStatus', {
    txid: txid
  }).then(r => {
    return r.data.getTransactionStatus
  })
}

/**
 * Validate the given credential by calling into the smart contract.
 *
 * @param {String} credentialAddressString Credential to check.
 * @returns {Promise.<boolean>} Status indicating valid address
*/
ValidateService.prototype.validateCredential = function (credentialAddressString) {
  return validate(this.httpClient, credentialAddressString)
}

/**
 * Validate given claim(s) by calling into the smart contract.
 *
 * @param {String|Array.<string>} claimSerialNumbers Array of claim serial numbers.
 * @returns {Promise.<boolean>} Status indicating valid address
*/
ValidateService.prototype.validateClaims = function (claimSerialNumbers) {
  var serialNumbers
  if (claimSerialNumbers instanceof Array) {
    serialNumbers = claimSerialNumbers.map(Utils.serialToAddress).join(',')
  } else {
    serialNumbers = Utils.serialToAddress(claimSerialNumbers)
  }
  return validate(this.httpClient, serialNumbers)
}

/**
 * @typedef KeyInfo
 * @type {object}
 * @property {boolean} isRevoked whether the address was revoked
 * @property {number} timestamp the unix-epoch timestamp of the last operation
 * @property {string} revokedBy the address of the revoker
 * @property {string} replaces the address of the credential that is replaced by this
 * @property {string} recovery the address of the registered recovery key
 * @property {string} rootAddress the root address of this credential
 *
 * @typedef {Object.<string,KeyInfo>} KeyInfoMap
 */

/**
 * Get extensive key information for given address.
 *
 * @param {String|Array.<string>} address blockchain address(es) of claim/credential to query
 * @returns {Promise.<KeyInfoMap>} KeyInfoMap structure from smart contract
*/
ValidateService.prototype.keyInfo = function (address) {
  if (address instanceof Array) {
    address = address.join(',')
  }
  return this.httpClient.get('keyInfo', {address: address})
    .then(r => r.data)
}
