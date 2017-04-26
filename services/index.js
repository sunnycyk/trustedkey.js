const CredentialRegistryService = require('./credentialregistryservice')
const TokenIssuerService        = require('./tokenissuerservice')
const TrustedKeyIssuerService   = require('./trustedkeyissuerservice')
const ValidateService           = require('./validateservice')
const WalletService             = require('./walletservice')


/**
 * Convienience wrapper to instantiate all services in a single namespace
 *
 * Instances are put into an attribute called shared.
 *
 * @constructor
*/
const services = module.exports = function(backendUrl) {
    this.credentialRegistryService = new CredentialRegistryService(backendUrl)
    this.tokenIssuerService = new TokenIssuerService(backendUrl)
    this.trustedKeyIssuerService = new TrustedKeyIssuerService(backendUrl)
    this.validateService = new ValidateService(backendUrl)
    this.walletService = new WalletService(backendUrl)
}


// Help editors to autocomplete
services.credentialRegistryService = undefined
services.tokenIssuerService = undefined
services.trustedKeyIssuerService = undefined
services.validateService = undefined
services.walletService = undefined
