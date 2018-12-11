//
//  recoveryUtils.js
//
//  Copyright © 2018 Trusted Key Solutions. All rights reserved.
//

const Crypto = require('crypto')

/**
 * @param {string|Array.<string>} wordList Array or Space-seperated words
 * @param {string} [passphrase] Optional salt
 * @returns {Promise.<Buffer>} Generated key
 */
exports.deriveKeyFromWordList = function (wordList, passphrase) {
  if (Array.isArray(wordList)) {
    wordList = wordList.join(' ')
  }
  const salt = passphrase || 'Trusted Key'
  return new Promise((resolve, reject) => {
    Crypto.pbkdf2(wordList, salt, 10000, 32, 'sha256', (err, key) => err ? reject(err) : resolve(key))
  })
}
