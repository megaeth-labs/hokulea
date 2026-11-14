# Frozen Steel boundary fixtures

These files are immutable, offline inputs. They do not trigger RPC or DA acquisition.

- `final-23.rlp` is the 677-byte Sepolia header captured at block 12,104,721. SHA-256: `97375c13577eb31e6e6e11992314ebc2cf05ae5eb9bf161d9b96e9cc4265a372`; expected block hash: `0x49482846ccac74bbd3820e234d0c0f8623edafb6075b771c12896d8e44668e53`. It contains the block-access-list hash and slot number.
- `sepolia-12109137-evm-input.bin` is the exact authenticated Steel `EthEvmInput` saved by the accepted held Sepolia native run. SHA-256: `833e1b8f8c3d977328621b81832198ff20d40e37288ddcadd68bd60d87a22748`; expected trusted head: `0xc00bb482113d9fd6578d356c391570f6830561ecb0603221e68ce55493909413` at block 12,109,137, timestamp 1,794,368,376, slot 11,552,898, and BAL hash `0x03fe3f2a70e59ad1b0791dd956dce48967ce57743c6b2c40fe51b0a2ac5f7aad`.

Original source locators:

- `/home/ubuntu/workspace/ai-office/worktrees/glam-kailua-kona121-consumer-20261113/crates/prover/tests/fixtures/l1-header-boundary/final-23.rlp`
- `/home/ubuntu/workspace/ai-office/evidence/GLAM-001/kailua-sepolia-state-gap-recovery-e2e-20261111/C/qualifying-native-01/native/native-result/canoe-proof.bin`

The input boundary test proves deserialization of the production `EthEvmInput`, authenticated state-root construction by `into_env`, the trusted-head hash, complete post-Glamsterdam header retention, and effective Sepolia fork selection. Prior accepted held-runtime evidence remains the proof for the five real certificate calls and end-to-end guest behavior; this fixture test does not claim a new proof or chain observation.
