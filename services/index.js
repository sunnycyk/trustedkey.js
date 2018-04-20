const CredentialRegistryService = require('./credentialregistryservice')
const ClaimIssuerService        = require('./claimissuerservice')
const TrustedKeyIssuerService   = require('./trustedkeyissuerservice')
const ValidateService           = require('./validateservice')
const WalletService             = require('./walletservice')


/**
 * Convienience wrapper to instantiate all services in a single namespace
 *
 * @exports services
 * @constructor
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
 * @param {String} issuerBaseUrl - The base issuer backend URL
 * @param {String} walletBaseUrl - The base wallet backend URL
*/
const services = module.exports = function(appId, appSecret, issuerBaseUrl, walletBaseUrl) {
    this.credentialRegistryService = new CredentialRegistryService(issuerBaseUrl, appId, appSecret)
    this.claimIssuerService = new ClaimIssuerService(issuerBaseUrl, appId, appSecret)
    this.trustedKeyIssuerService = new TrustedKeyIssuerService(issuerBaseUrl, appId, appSecret)
    this.validateService = new ValidateService(issuerBaseUrl, appId, appSecret)
    this.walletService = new WalletService(walletBaseUrl, appId, appSecret)
}


/**
 * CredentialRegistryService instance
 *
 * @type {CredentialRegistryService}
*/
services.credentialRegistryService = undefined

/**
 * ClaimIssuerService instance
 *
 * @type {ClaimIssuerService}
*/
services.claimIssuerService = undefined

/**
 * TrustedKeyIssuerService instance
 *
 * @type {TrustedKeyIssuerService}
*/
services.trustedKeyIssuerService = undefined

/**
 * ValidateService instance
 *
 * @type {ValidateService}
*/
services.validateService = undefined

/**
 * WalletService instance
 *
 * @type {WalletService}
*/
services.walletService = undefined
