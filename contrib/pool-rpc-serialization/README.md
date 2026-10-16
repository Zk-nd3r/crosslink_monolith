# pool key byte order fix

our pool decoded Monolith's RPC public keys and copied them straight onto the wire. those JSON keys are reversed. the wire needs the original 32 bytes.

fixed by reversing the decoded key buffer once. vote bytes, signatures and signer order stay unchanged. the input RPC object is untouched.

[patch](key-byte-order.patch) | [corrected adapter](crosslinkFatPointer.js)

this is our custom S-NOMP adapter, shared on our fork for pools using the same setup. it is not in the upstream S-NOMP or Valar pool trees we checked. this package is not a complete pool integration or an upstream consensus change.

Monolith v15 defines the encoding in [`bft.rs`](https://github.com/ShieldedLabs/crosslink_monolith/blob/68a076cf3c866c339a89b5684eccea64a4229d7a/librustzcash/zcash_primitives/src/bft.rs): `PubKeyID` JSON at lines 703-732, raw signature keys at lines 979-988. the native JSON encoding is intentional.

## test

Node 18+, no dependencies or network calls:

```sh
node test.js
```

- three full block hashes reproduced.
- 50,309 and 50,310: same vote and ten signatures, every key reversed. old code reproduces the fault; fixed code matches the original correct bytes.
- 55,673: nine signatures verify as encoded after the fix.
- 19 valid signatures pass, 19 tampered signatures fail, all ten wrongly encoded historical entries fail.
- repeat calls leave the input unchanged. malformed keys fail.

RPC-shaped inputs are reconstructed from public headers, not captured historical RPC templates. these fixtures use the zero signing namespace. the test checks bytes and signatures, not roster quorum, Equihash or full consensus.

`node test.js --serialization-only` also passes on the pool's Node 10.24.1 runtime. that mode skips signature verification and says so in its output.

## apply

only for an adapter using this same RPC-to-wire conversion. back up the current file, then run from the `stratum-pool` package root:

```sh
git apply --check /path/to/key-byte-order.patch
git apply /path/to/key-byte-order.patch
```

for an identical setup, the corrected file can replace `lib/crosslinkFatPointer.js`. test it locally, reload the affected pool and verify a new certificate as encoded. there is no installer or live action in this package. do not reverse keys already in raw wire order.

the supplied file is byte-for-byte the deployed version, including CRLF line endings:

```text
0c40fe0e89fabe60b594719011b31236ec4d0c675141814fab8f6d8453ec740c
```

applying the text patch may keep a different newline convention. equivalent code can therefore have a different file hash. `SHA256SUMS` covers the supplied files.

## limits

pool serialization is fixed. protocol certificate validation and binding the pointer to Equihash remain separate work.

correcting keys in a diagnostic copy does not repair the historical block. these fixtures do not establish how anyone mined.

the adapter trusts native RPC templates. it does not enforce roster membership, quorum or v15's 12-entry limit. it is not a certificate validator.
