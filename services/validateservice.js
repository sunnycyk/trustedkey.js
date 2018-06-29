const Assert = require('assert')
const Utils = require('../utils')
const RP = require('request-promise-native')

/**
 * An implementation of a the validation API, used to check to validity of credentials and claims.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 */
const ValidateService = module.exports = function (backendUrl) {
  this.httpClient = {
    get: function (url, params) {
      const uri = Utils.mergeQueryParams(url, params || {})
      return RP({baseUrl: backendUrl, url: uri, json: true})
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
 * @param {String} txid - Transaction ID to check.
 * @returns {Promise} Transaction status object
*/
ValidateService.prototype.getTransactionStatus = function (txid) {
  Assert.strictEqual(typeof txid, 'string', 'txid must be of type `string`')

  return this.httpClient.get('getTransactionStatus', {
    txid: txid
  }).then(r => {
    return r.data
  })
}

/**
 * Validate the given credential by calling into the smart contract.
 *
 * @param {String} credentialAddressString - Credential to check.
 * @returns {boolean} Status indicating valid address
*/
ValidateService.prototype.validateCredential = function (credentialAddressString) {
  return validate(this.httpClient, credentialAddressString)
}

/**
 * Validate given claim(s) by calling into the smart contract.
 *
 * @param {String|Array} claimSerialNumbers - Array of claim serial numbers.
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
 * Get extensive key information for given address.
 *
 * @param {String|Array} address - blockchain address(es) of claim/credential to query
 * @returns {object} KeyInfo structure from smart contract
*/
ValidateService.prototype.keyInfo = function (address) {
  if (address instanceof Array) {
    address = address.join(',')
  }
  return this.httpClient.get('keyInfo', {address: address})
    .then(r => r.data)
}
