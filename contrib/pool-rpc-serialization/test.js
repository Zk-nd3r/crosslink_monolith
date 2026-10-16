'use strict';

// Offline regression only. No RPC, mining, signing, or block submission.
const assert = require('assert');
const crypto = require('crypto');
const before = require('./fixtures/crosslinkFatPointer.before.js');
const after = require('./crosslinkFatPointer.js');
const fixture = require('./fixtures/headers.json');
const serializationOnly = process.argv.includes('--serialization-only');
if (!serializationOnly) {
    assert.strictEqual(typeof crypto.verify, 'function', 'Use Node 18+ for Ed25519 verification');
}

const expectedHashes = {
    50309: '0000051d91c0b0d02a2300c86c24fcb58ec6e9ff094f39f5a654595f95b9fdda',
    50310: '000023e298ae72e56092594025bebbf20c97b4971d949a5fac71c731002ff5d1',
    55673: '000032f158b98e0c1371352848d9f997f9b4a1705b61101516bc48b07d779f03'
};

function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest();
}

function parseHeader(row) {
    const header = Buffer.from(row.raw_header, 'hex');
    assert.strictEqual(row.hash, expectedHashes[row.height]);
    assert.strictEqual(sha256(sha256(header)).reverse().toString('hex'), row.hash);
    // These pinned N=200,K=9 fixtures have a 1344-byte Equihash solution.
    assert.strictEqual(header.subarray(140, 143).toString('hex'), 'fd4005');
    const wire = header.subarray(143 + 1344);
    const vote = wire.subarray(0, 44);
    const count = wire.readUInt16LE(44);
    assert.strictEqual(wire.length, 46 + count * 96);
    const signers = [];
    for (let i = 0; i < count; i++) {
        const offset = 46 + 96 * i;
        signers.push({key: wire.subarray(offset, offset + 32), signature: wire.subarray(offset + 32, offset + 96)});
    }
    return {wire, vote, signers};
}

function asRpc(certificate) {
    return {
        version: 6,
        fat_pointer_to_bft_block: {
            vote_for_block_without_finalizer_public_key: Array.from(certificate.vote),
            signatures: certificate.signers.map(function (entry) {
                return {pub_key: Buffer.from(entry.key).reverse().toString('hex'), vote_signature: Array.from(entry.signature)};
            })
        }
    };
}

function verifies(key, signature, vote) {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key]);
    return crypto.verify(null, Buffer.concat([key, vote]), {key:spki, format:'der', type:'spki'}, signature);
}

const blocks = {};
fixture.blocks.forEach(function (row) {
    assert(!blocks[row.height], 'Duplicate fixture height');
    blocks[row.height] = parseHeader(row);
});
assert.deepStrictEqual(Object.keys(blocks).sort(), ['50309', '50310', '55673']);
const correct = blocks[50309];
const faulty = blocks[50310];
const deployed = blocks[55673];
assert.deepStrictEqual(correct.vote, faulty.vote);
assert.strictEqual(correct.signers.length, 10);
assert.strictEqual(faulty.signers.length, 10);
assert.strictEqual(deployed.signers.length, 9);
correct.signers.forEach(function (entry, i) {
    assert.deepStrictEqual(entry.signature, faulty.signers[i].signature);
    assert.deepStrictEqual(Buffer.from(entry.key).reverse(), faulty.signers[i].key);
});

const rpc = asRpc(correct);
const frozenInput = JSON.stringify(rpc);
assert.deepStrictEqual(before.serialize(rpc), faulty.wire, 'Reproduce old faulty wire bytes');
assert.deepStrictEqual(after.serialize(rpc), correct.wire, 'Match original correct wire bytes');
assert.deepStrictEqual(after.serialize(rpc), correct.wire, 'Repeat serialization is stable');
assert.strictEqual(JSON.stringify(rpc), frozenInput, 'RPC input must remain unchanged');
assert.deepStrictEqual(after.serialize(asRpc(deployed)), deployed.wire);

// A small asymmetric synthetic input makes the byte-order contract explicit.
const syntheticKey = Buffer.from(Array.from({length:32}, function (_, i) { return i; }));
const synthetic = JSON.parse(frozenInput);
synthetic.fat_pointer_to_bft_block.signatures[0].pub_key = Buffer.from(syntheticKey).reverse().toString('hex');
assert.deepStrictEqual(after.serialize(synthetic).subarray(46, 78), syntheticKey);

['00', 'zz'.repeat(32), null].forEach(function (badKey) {
    const malformed = JSON.parse(frozenInput);
    malformed.fat_pointer_to_bft_block.signatures[0].pub_key = badKey;
    assert.throws(function () { after.serialize(malformed); });
});
const uppercase = JSON.parse(frozenInput);
uppercase.fat_pointer_to_bft_block.signatures.forEach(function (entry) { entry.pub_key = entry.pub_key.toUpperCase(); });
assert.deepStrictEqual(after.serialize(uppercase), correct.wire);
assert.strictEqual(after.serialize({version:4}).length, 0);
assert.throws(function () { after.serialize({version:6}); });
const version5 = JSON.parse(frozenInput);
version5.version = 5;
assert.deepStrictEqual(after.serialize(version5), correct.wire);

let valid = 0;
let rejected = 0;
if (!serializationOnly) {
    [correct, deployed].forEach(function (certificate) {
        certificate.signers.forEach(function (entry) {
            assert(verifies(entry.key, entry.signature, certificate.vote));
            valid++;
            const tampered = Buffer.from(entry.signature);
            tampered[0] ^= 1;
            assert(!verifies(entry.key, tampered, certificate.vote));
            rejected++;
        });
    });
    faulty.signers.forEach(function (entry) {
        assert(!verifies(entry.key, entry.signature, faulty.vote), 'Historical bytes are invalid as encoded');
    });
}
console.log(JSON.stringify({status:'PASS', scope:'offline regression', header_hashes_verified:3,
    historical_fault_reproduced:true, valid_signatures:serializationOnly ? null : valid,
    tampered_signatures_rejected:serializationOnly ? null : rejected,
    historical_invalid_signatures_rejected:serializationOnly ? null : 10,
    signature_verification:serializationOnly ? 'SKIPPED: serialization compatibility check only' : 'PASS',
    input_unchanged:true, runtime:process.version}));
