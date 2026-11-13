# Vendored Steel production closure

This directory preserves the exact reviewed source-only Steel closure accepted in the Kona 1.2.1 Kailua consumer work. It is repository-relative because the required post-Glamsterdam header and RISC Zero guest-compatible precompile support were not available from the previously selected Steel 2.4.0 tag.

Sources copied byte-for-byte before the explicit Hokulea chain-schedule adaptation:

- `steel/`: accepted `risc0-steel` 3.0.0 source, Apache-2.0. Frozen deterministic tar SHA-256 `aae34daaacdb990a37563dcd4af6e1d031a15604133e776479b9d45292ed7543`.
- `revm-precompile-l1/`: REVM precompile 43.0.3 source, MIT. Frozen deterministic tar SHA-256 `1f1364895206e65dad2b4d0b33bd726b5bffca89906fdceb11da0bb8191b9118`.

Frozen evidence source:

`/home/ubuntu/workspace/ai-office/evidence/GLAM-001/kona121-release-hokulea-kailua-update-20261113/C/source-delivery/source/vendor`

Hokulea intentionally changes only `steel/crates/steel/src/ethereum.rs` after that copy: it adds the independently frozen Sepolia Amsterdam activation at timestamp `1791294816` and retains the prior Holešky schedule. Host, verifier, and nested RISC Zero guest all select this same package and schedule. No Steel or precompile crate is separately published by this tag.

The schedule's selected-source `ChainSpec::digest()` is `4c6a19fd3ca4a019f3ab60f4485b4f4043ad076070c9a5cc2d6381f817f5ee62`. It is structural SHA-256 over the ordered `(SpecId, ForkCondition)` entries and chain ID, independent of the held block and journal fixtures. This source-only package does not include or deploy upstream Steel Solidity contracts, so there is no `Steel.sol` constant in the tag to synchronize; the Rust digest guard and the consuming Hokulea verifier/guest are the relevant surfaces.
