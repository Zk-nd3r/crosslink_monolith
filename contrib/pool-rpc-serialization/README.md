# Crosslink pool public-key serialization fix

This is the deployed fix for our custom S-NOMP Crosslink adapter, shared for operators using the same RPC-to-wire conversion. It is a standalone review package on this fork. It does not change Monolith consensus or imply upstream acceptance.

The native RPC encodes `PubKeyID` as `hex(reverse(raw_key))`. A fat-pointer signature on the wire stores the original 32 key bytes. Our adapter decoded the RPC hex without reversing those bytes. The fix reverses the newly allocated key buffer once. Vote bytes, signatures, signer order and the input RPC object stay unchanged.

```diff
-parts.push(hexBytes(signature.pub_key, 32, field));
+parts.push(hexBytes(signature.pub_key, 32, field).reverse());
```

The exact patch is [key-byte-order.patch](key-byte-order.patch). The complete corrected file is [crosslinkFatPointer.js](crosslinkFatPointer.js). The illustrative `field` above stands for the unchanged diagnostic string in that patch.

The encoding contract is defined in Monolith v15 commit [`68a076cf3c866c339a89b5684eccea64a4229d7a`](https://github.com/ShieldedLabs/crosslink_monolith/blob/68a076cf3c866c339a89b5684eccea64a4229d7a/librustzcash/zcash_primitives/src/bft.rs): `PubKeyID` serde at lines 703-732 and `FatPointerSignature` wire serialization at lines 979-988. The native JSON encoding is intentional.

## Test

No dependencies or network access are needed. Run with Node 18 or later:

```sh
node test.js
```

The public raw-header fixtures reproduce three full block hashes. Blocks 50,309 and 50,310 carry the same vote and ten signature byte strings, with every key reversed between the two. The old serializer reproduces 50,310's faulty pointer. The corrected serializer matches 50,309's original pointer. Block 55,673 supplies a separate post-fix fixture with nine signatures valid as encoded.

The test verifies 19 Ed25519 signatures, rejects 19 tampered signatures and the ten incorrectly encoded historical entries, checks immutable/repeatable serialization, and rejects malformed keys. RPC-shaped input is reconstructed from the headers using the native serde contract; it is not a captured historical RPC template. Signature checks use the zero namespace applicable to these fixtures. This is not a historical quorum or full consensus audit, and it does not validate Equihash.

`node test.js --serialization-only` checks compatibility on the pool's older Node runtime without running Ed25519 verification. It reports the skipped checks explicitly.

## Apply to the matching adapter

This adapter is not present in the upstream S-NOMP or Valar pool trees inspected for this package. It is not a complete Crosslink pool integration. Use the patch only if your adapter has the same RPC input contract and the matching old line:

```sh
# From the stratum-pool package root, after preserving your current file:
git apply --check /path/to/key-byte-order.patch
git apply /path/to/key-byte-order.patch
```

For an identical installation, the complete corrected file can replace `lib/crosslinkFatPointer.js` after local review. Stage and test your integration, reload the affected pool according to its deployment method, and verify a newly constructed certificate as encoded. This package has no installer and performs no live changes. Do not reverse keys that are already in raw wire order.

The supplied corrected file retains the deployed CRLF bytes and has SHA-256 `0c40fe0e89fabe60b594719011b31236ec4d0c675141814fab8f6d8453ec740c`. The textual patch may retain your installation's newline convention, depending on Git settings, so its file hash can differ despite equivalent JavaScript. `SHA256SUMS` lists the exact distributed files.

## Scope

This corrects the pool's serialization error. It does not fix the separate protocol issues involving certificate admission or binding the fat pointer to Equihash. Correcting a copied historical key is a diagnostic comparison, not retroactive validation of the original block's encoded signature. These fixtures do not establish any miner's historical search strategy.

The serializer trusts native RPC templates. Its inherited checks do not enforce roster membership, quorum, or v15's 12-entry consensus limit; it is not a certificate validator.
