//
//  errors.js
//
//  Copyright © 2016 Trusted Key Solutions. All rights reserved.
//

/**
 * Internal custom errors
*/
const errors = module.exports = {}

errors.ApplicationError = function(message) {
    Error.captureStackTrace(this)
    this.message = message
    this.name = "ApplicationError"
}

errors.ApplicationError.prototype = Object.create(Error.prototype)


errors.InternalError = function(message) {
    Error.captureStackTrace(this)
    this.message = message
    this.name = "InternalError"
}

errors.InternalError.prototype = Object.create(Error.prototype)
