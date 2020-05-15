const BN = require('bn.js')

const keypair = require('../index.js')

let aion = keypair.from_private_key(
    'aion', 
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
) 

const sign = aion.sign
const signed = sign({
    nonce: new BN(10),
    to: '0xa000000000000000000000000000000000000000000000000000000000000000',
    data: '',
    timestamp: new Date().getTime() * 1000,
    amount: new BN(10),
    gasPrice: new BN(10000000000),
    gasLimit: new BN(2000000),
    type: new BN(1)
})
console.log('[signed]', signed)

const unsigned = keypair.unsign('aion', signed)
console.log('[unsigned]', unsigned)