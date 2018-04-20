const Assert = require('assert')
const Utils = require('../utils')
const RP = require('request-promise-native')


/**
 * An implementation of a the validation API, used to check to validity of credentials and claims.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 */
const ValidateService = module.exports = function(backendUrl) {
    this.httpClient = {
        get: function(url, params) {
            const uri = Utils.mergeQueryParams(url, params||{})
            return RP({baseUrl: backendUrl, url: uri, json: true})
        }
    }
}


function validate(httpClient, address) {

    Assert.strictEqual(typeof address, "string", 'address must be of type `string`')

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
ValidateService.prototype.getTransactionStatus = function(txid) {

    Assert.strictEqual(typeof txid, "string", 'txid must be of type `string`')

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
ValidateService.prototype.validateCredential = function(credentialAddressString) {
    return validate(this.httpClient, credentialAddressString)
}


/**
 * Validate given claim(s) by calling into the smart contract.
 *
 * @param {string} claimSerialNumbers - Array of claim serial numbers.
 * @returns {boolean} Status indicating valid address
*/
ValidateService.prototype.validateClaims = function(claimSerialNumbers) {
    var serialNumbers
    if(typeof claimSerialNumbers !== 'string') {
        serialNumbers = claimSerialNumbers.map(serialNo => {
            if(serialNo.match(/^0x/)) {
                return serialNo
            } else {
                return '0x' + serialNo
            }
        }).join(',')
    } else {
        serialNumbers = claimSerialNumbers
    }
    return validate(this.httpClient, serialNumbers)
}


/**
 * Get extensive key information for given address.
 *
 * @param {string} address - blockchain address of claim/credential to query
 * @returns {object} KeyInfo structure from smart contract
*/
ValidateService.prototype.keyInfo = function(address) {

    Assert.strictEqual(typeof address, "string", 'address must be of type `string`')

    return this.httpClient.get('keyInfo', {address: address})
        .then(r => r.data)
}
