const BN = require('bn.js')
const nacl = require('tweetnacl')
const blake2b = require('blake2b')
const rlp = require('aion-rlp')
const util = require('../util.js')

/**
 * Generate keypair from private key
 * 
 * @param {string} private_key 
 * 
 * @returns {
 *      {string} private_key,
 *      {string} public_key,
 *      {string} address,
 *      {function} sign
 * }
 */
function from_private_key(private_key) {
    const buf = Buffer.from(private_key, 'hex')
    const pair = nacl.sign.keyPair.fromSeed(buf)
    const hash = blake2b(32).update(pair.publicKey).digest()
    hash[0] = 0xa0
    let keypair = {
        private_key, 
        public_key: Buffer.from(pair.publicKey).toString('hex'), 
        address: Buffer.from(hash).toString('hex')
    }
    keypair.sign = (tx) => {

        let array = [
            tx.nonce,
            tx.to,
            tx.amount,
            tx.data,
            tx.timestamp,
            new rlp.AionLong(tx.gasLimit),
            new rlp.AionLong(tx.gasPrice),
            new rlp.AionLong(tx.type)
        ]
        let tx_rlped = rlp.encode(array)
        let digest = blake2b(32).update(tx_rlped).digest()
        let key = Buffer.from(this.private_key + this.public_key, 'hex')
        let signature_buffer = Buffer.from(nacl.sign.detached(digest, key))
        signature_buffer = Buffer.concat([
            Buffer.from(this.public_key, 'hex'), 
            signature_buffer
        ])
        let signature = signature_buffer.toString('hex')
        return rlp.encode(rlp.decode(tx_rlped).concat(signature)).toString('hex')
    }
    return keypair
}

/**
 * Static sign raw transaction
 * 
 * @param {string} signed 
 * @param {string} private_key // 64 hex characters
 * @param {string} public_key  // 64 hex characters
 * 
 * @return {
    *      {BN} nonce,
    *      {string} to,
    *      {BN} amount,
    *      {string} data,
    *      {number} timestamp
    *      {BN} gas_limit,
    *      {BN} gas_price,
    *      {BN} type
    * }
    */
function sign(tx, private_key, public_key) {
    let array = [
        tx.nonce,
        tx.to,
        tx.amount,
        tx.data,
        tx.timestamp,
        new rlp.AionLong(tx.gasLimit),
        new rlp.AionLong(tx.gasPrice),
        new rlp.AionLong(tx.type)
    ]
    let tx_rlped = rlp.encode(array)
    let digest = blake2b(32).update(tx_rlped).digest()
    let key = Buffer.from(private_key + public_key, 'hex')
    let signature_buffer = Buffer.from(nacl.sign.detached(digest, key))
    signature_buffer = Buffer.concat([
        Buffer.from(public_key, 'hex'), 
        signature_buffer
    ])
    let signature = signature_buffer.toString('hex')
    return rlp.encode(rlp.decode(tx_rlped).concat(signature)).toString('hex')
}

/**
 * Static unsign raw transaction
 * 
 * @param {string} signed 
 * 
 * @return {
 *      {BN} nonce,
 *      {string} to,
 *      {BN} amount,
 *      {string} data,
 *      {number} timestamp
 *      {BN} gas_limit,
 *      {BN} gas_price,
 *      {BN} type
 * }
 */
function unsign(signed){
    let array = rlp.decode(Buffer.from(signed, 'hex'))
    let nonce = new BN(array[0]),
        to = util.format_hex(array[1].toString('hex')),
        amount = new BN(array[2]),
        data = array[3].toString('hex'),
        timestamp = parseInt(array[4].toString('hex'), 16),
        gas_limit = new BN(array[5]),
        gas_price = new BN(array[6]),
        type = new BN(array[7])

    return {
        nonce,
        to,
        amount,
        data,
        timestamp,
        gas_limit,
        gas_price,
        type
    }
}

module.exports = {
    from_private_key,
    unsign
}