# Held Sepolia production inputs

`sepolia-12109137-canoe-inputs.bin` is a bincode-encoded `Vec<CanoeInput>` reconstructed from the immutable accepted Kailua Sepolia run's `consumed-preimage.bin`. It contains the five certificate/claimed-validity pairs and their deployed EigenLabs verifier addresses; it contains no RPC response or runtime cache.

The matching authenticated Steel state input is `../../../verifier/tests/fixtures/sepolia-12109137-evm-input.bin`. Both inputs bind Sepolia head 12,109,137, hash `c00bb482113d9fd6578d356c391570f6830561ecb0603221e68ce55493909413`, and timestamp 1,794,368,376.

Fixture SHA-256: `609f5632ceb992d4e816b50f217f11100217507fe65667a7e109a7f1829a91f1` (5,813 bytes).
