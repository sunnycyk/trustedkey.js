const CredentialRegistryService = require('./credentialregistryservice')
const TokenIssuerService        = require('./tokenissuerservice')
const TrustedKeyIssuerService   = require('./trustedkeyissuerservice')
const ValidateService           = require('./validateservice')
const WalletService             = require('./walletservice')


/**
 * Convienience wrapper to instantiate all services in a single namespace
 *
 * @exports services
 * @constructor
 * @param {String} backendUrl - The base backend URL
 * @param {String} [appId] - Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] - Application shared secret, without this only unauthorized APIs can be used
*/
const services = module.exports = function(backendUrl, appId, appSecret) {
    this.credentialRegistryService = new CredentialRegistryService(backendUrl, appId, appSecret)
    this.tokenIssuerService = new TokenIssuerService(backendUrl, appId, appSecret)
    this.trustedKeyIssuerService = new TrustedKeyIssuerService(backendUrl, appId, appSecret)
    this.validateService = new ValidateService(backendUrl, appId, appSecret)
    this.walletService = new WalletService(backendUrl, appId, appSecret)
}


/**
 * CredentialRegistryService instance
 *
 * @type {CredentialRegistryService}
*/
services.credentialRegistryService = undefined

/**
 * TokenIssuerService instance
 *
 * @type {TokenIssuerService}
*/
services.tokenIssuerService = undefined

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
