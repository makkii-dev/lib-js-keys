function format_hex(hex){
    if(typeof hex !== 'string')
        return '0x'
    if(hex.indexOf('0x') >= 0)
        hex = hex.substring(2, hex.length)
    if(hex.length % 2 == 1)
        hex = '0' + hex
    return '0x' + hex   
}

module.exports = {
    format_hex
}