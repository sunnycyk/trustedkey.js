const Assert = require('assert')
const HttpUtils = require('./http')


/**
 * An implementation of a the validation API, used to check to validity of credentials and tokens.
 *
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 */
const ValidateService = module.exports = function(backendUrl, appId, appSecret) {
    this.httpClient = new HttpUtils(backendUrl, appId, appSecret)
}


function validate(httpClient, address) {

    Assert.strictEqual(typeof address, "string", `address must be of type "string"`)

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

    Assert.strictEqual(typeof txid, "string", `txid must be of type "string"`)

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
 * Validate given token(s) by calling into the smart contract.
 *
 * @param {string} tokenSerialNumbers - Array of token serial numbers.
 * @returns {boolean} Status indicating valid address
*/
ValidateService.prototype.validateTokens = function(tokenSerialNumbers) {
    var serialNumbers
    if(typeof tokenSerialNumbers !== 'string') {
        serialNumbers = tokenSerialNumbers.map(serialNo => {
            if(serialNo.match(/^0x/)) {
                return serialNo
            } else {
                return '0x' + serialNo
            }
        }).join(',')
    } else {
        serialNumbers = tokenSerialNumbers
    }
    return validate(this.httpClient, serialNumbers)
}
