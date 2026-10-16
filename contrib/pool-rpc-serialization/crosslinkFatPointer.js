'use strict';

function byteArray(value, expectedLength, field) {
    if (!Array.isArray(value) || value.length !== expectedLength) {
        throw new Error(field + ' must contain exactly ' + expectedLength + ' bytes');
    }
    for (var i = 0; i < value.length; i++) {
        if (!Number.isInteger(value[i]) || value[i] < 0 || value[i] > 255) {
            throw new Error(field + '[' + i + '] is not a byte');
        }
    }
    return Buffer.from(value);
}

function hexBytes(value, expectedLength, field) {
    if (typeof value !== 'string' || value.length !== expectedLength * 2 || !/^[0-9a-fA-F]+$/.test(value)) {
        throw new Error(field + ' must be exactly ' + expectedLength + ' hex bytes');
    }
    return Buffer.from(value, 'hex');
}

function serialize(rpcData) {
    if (!rpcData || !Number.isInteger(rpcData.version)) {
        throw new Error('block template version is required');
    }
    if (rpcData.version < 5) {
        return Buffer.alloc(0);
    }

    var pointer = rpcData.fat_pointer_to_bft_block;
    if (!pointer || typeof pointer !== 'object') {
        throw new Error('version >= 5 requires fat_pointer_to_bft_block');
    }

    var signatures = pointer.signatures;
    if (!Array.isArray(signatures) || signatures.length > 0xffff) {
        throw new Error('fat pointer signatures must be an array of at most 65535 entries');
    }

    var count = Buffer.alloc(2);
    count.writeUInt16LE(signatures.length, 0);
    var parts = [
        byteArray(pointer.vote_for_block_without_finalizer_public_key, 44, 'fat pointer vote'),
        count
    ];

    signatures.forEach(function (signature, index) {
        if (!signature || typeof signature !== 'object') {
            throw new Error('fat pointer signature[' + index + '] must be an object');
        }
        // RPC PubKeyID hex is reversed display order; consensus wire needs raw bytes.
        parts.push(hexBytes(signature.pub_key, 32, 'fat pointer signature[' + index + '].pub_key').reverse());
        parts.push(byteArray(signature.vote_signature, 64, 'fat pointer signature[' + index + '].vote_signature'));
    });

    return Buffer.concat(parts);
}

module.exports = { serialize: serialize };
