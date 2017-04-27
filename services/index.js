const CredentialRegistryService = require('./credentialregistryservice')
const TokenIssuerService        = require('./tokenissuerservice')
const TrustedKeyIssuerService   = require('./trustedkeyissuerservice')
const ValidateService           = require('./validateservice')
const WalletService             = require('./walletservice')
const Jsrsasign                 = require('jsrsasign')


/**
 * Convienience wrapper to instantiate all services in a single namespace
 *
 * Instances are put into an attribute called shared.
 *
 * @exports services
 * @constructor
*/
const services = module.exports = function(backendUrl, appKeyPair) {
    var appKeyP = appKeyPair || Jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1").prvKeyObj

    this.credentialRegistryService = new CredentialRegistryService(backendUrl, appKeyP)
    this.tokenIssuerService = new TokenIssuerService(backendUrl, appKeyP)
    this.trustedKeyIssuerService = new TrustedKeyIssuerService(backendUrl, appKeyP)
    this.validateService = new ValidateService(backendUrl, appKeyP)
    this.walletService = new WalletService(backendUrl, appKeyP)
}


/**
 * CredentialRegistryService instance
*/
services.credentialRegistryService = undefined

/**
 * TokenIssuerService instance
*/
services.tokenIssuerService = undefined

/**
 * TrustedKeyIssuerService instance
*/
services.trustedKeyIssuerService = undefined

/**
 * ValidateService instance
*/
services.validateService = undefined

/**
 * WalletService instance
*/
services.walletService = undefined
