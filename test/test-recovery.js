/* eslint-env mocha */
const RecoveryUtils = require('../recoveryUtils')
const Assert = require('assert')

describe('RecoveryUtils', function () {
  it('well-known', async function () {
    const key = await RecoveryUtils.deriveKeyFromWordList('reward cup cement tackle scout domain kidney few auction robust carbon discover', '111111')
    Assert.strictEqual(key.toString('hex'), 'ff958a07eba69089c19ba9644077e147b54e0a86a2e24df62bbe7571ba63fccf')
  })
})
