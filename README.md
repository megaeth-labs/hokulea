# Hokulea

> Hokulea is a Polynesian double-hulled voyaging canoe. Hōkūle‘a (“Star of Gladness”), a zenith star of Hawai‘i, which appeared to him growing ever brighter in a dream. [Source](https://worldwidevoyage.hokulea.com/vessels/hokulea/)

Hokulea is a library to provide the altda providers for a derivation pipeline built with [kona](https://github.com/anton-rs/kona) to understand eigenDA blobs, following the [kona book](https://op-rs.github.io/kona/protocol/derive/providers.html#implementing-a-custom-data-availability-provider) recommendation (also see this [comment](https://github.com/anton-rs/kona/pull/862#issuecomment-2515038089)).

## Dependencies

We use mise to track and manage dependencies. Please first [install mise](https://mise.jdx.dev/getting-started.html), and then run `mise install` to install the dependencies.

## SRS points
Hokulea's proving client currently computes a challenge proof that validates the correctness of the eigenda blob against the provided kzg commitment. Such computation requires the proving client to have access to sufficient KZG G1 SRS points. Currently the SRS points are (hardcoded) assumed to be located at `resources/g1.point`. You can download the SRS points to that location by running `just download-srs`, which downloads the `g1.point` file from the [eigenda repo](https://github.com/Layr-Labs/eigenda-proxy/tree/main/resources).

## Integrating with Hokulea

A complete overview of the integration pipeline can be found in the [documentation](./docs/README.md). For zkVM integration details, refer to the following sections:
- [Overview on data transformation for secure integration with zkVM](./docs/README.md#overview-on-data-transformation-for-secure-integration-with-zkvm)
- [Three implementation of EigenDAPreimageProvider trait and their differences](./docs/README.md#three-implementation-of-eigendapreimageprovider-trait-and-their-differences)

For a practical example of how the library can be integrated with a zkVM, see `example/preloader/main.rs`. (Note: this example includes mock elements for demonstration purposes.)
For real-world implementations, both Op-succinct and Kailua integrate Hokulea in their zkVM workflows:

- [Op-succinct client](https://github.com/succinctlabs/op-succinct/tree/main/programs/range/eigenda)
- [Op-succinct host](https://github.com/succinctlabs/op-succinct/tree/main/utils/eigenda/host)
- [Kailua client](https://github.com/boundless-xyz/kailua/tree/main/crates/hokulea/src)
- [Kailua host](https://github.com/boundless-xyz/kailua/tree/main/crates/prover/src/hokulea)

[documentation](./docs/README.md) is also applicable for other integrations, and pay special attention on the trust assumption on certain data structure.

### MegaETH Steel git dependency

Cargo does not propagate a git dependency's root `[patch]` table into the
consuming workspace. Consumers of the standalone Steel path in
`mega-hokulea/v1.0.8` must select the reviewed precompile from the same tag:

```toml
[dependencies]
canoe-steel-apps = { git = "https://github.com/megaeth-labs/hokulea", tag = "mega-hokulea/v1.0.8", version = "=0.1.1" }
canoe-steel-methods = { git = "https://github.com/megaeth-labs/hokulea", tag = "mega-hokulea/v1.0.8", version = "=0.1.1" }
canoe-steel-verifier = { git = "https://github.com/megaeth-labs/hokulea", tag = "mega-hokulea/v1.0.8", version = "=0.1.1" }

[patch.crates-io]
revm-precompile = { git = "https://github.com/megaeth-labs/hokulea", tag = "mega-hokulea/v1.0.8", package = "revm-precompile" }
```

With Rust 1.94.1, the reviewed downstream lock was produced and checked with:

```bash
cargo generate-lockfile
cargo update -p alloy-rlp --precise 0.3.16
cargo update -p alloy-rlp-derive --precise 0.3.16
cargo update -p risc0-zkvm --precise 3.0.3
cargo update -p risc0-build-ethereum --precise 3.0.1
cargo update -p risc0-build --precise 3.0.3
cargo update -p alloy-trie@0.9.9 --precise 0.9.8
RISC0_BUILD_LOCKED=1 cargo check --locked
```

The `alloy-trie` pin keeps Reth v1.9.1 on its compatible `HashBuilder` API;
the RLP and RISC Zero pins reproduce the versions validated by this source
snapshot. Commit the resulting consumer lockfile. Once dependencies are
cached, the same graph can be rechecked without network access by adding
`--offline`. Building `canoe-steel-methods` also requires the RISC Zero Rust
guest toolchain. This source-only tag does not include a prebuilt guest or
proof artifact.

## EigenDA proxy configuration
Hokulea relies on eigenda proxy for fetching preimage values, including `cert_validity` and `encoded_payload`. For cert validity and encode payload, the preimage comes from proxy and is verified later, whereas the recency window value is derived from hokulea directly.

In hokulea both V2 and V3 have set recency window default to 0. For V4, if the `offchain_derivation_version` is `0`, the recency window is 48hours.

## Local Manual Testing

We use kurtosis to start an [optimism-package](https://github.com/ethpandaops/optimism-package/tree/main) devnet, and run the hokulea host and client against it.

```bash
just run-kurtosis-devnet-with-eigenlabs-package
```

## Supported L1 Chain
Hokulea now supports Mainnet, Sepolia and Holesky. More in the future. However, chain id `3151908` is explicitly not supported for trustless secure integration. Hokulea uses kurtosis devnet with chain id `3151908` for testing. Proving against `3151908` will generate a ZK proof that cannot be verified by the `CanoeVerifier` implementation in this repo.

### Running the native client

```bash
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file. Temporary env variables are stored at
# .devnet.env and .run.devnet.env
just run-client-against-devnet 'native'
```

### Running on Asterisc

> :Warning: Building the client to run on asterisc currently doesn't work. We are spending most of our current effort on zk approaches instead, but we will eventually fix this.

You will first need to build the client against the correct arch. Run
```bash
just build-client-for-asterisc
```
Then you can run
```bash
just run-client-against-devnet 'asterisc'
```

### Risc0 and Sp1 toolchain installation

[Canoe](./canoe/) takes advantage of zkvm to create a validity proof that attestes the validity of DA certificates. The proof generation requires 
compiling rust code into a ELF file runnable within zkVM. The canoe crate in Hokulea is dedicated for such purpose.
Canoe currently supports two backends:
1. Steel(Risc0)
   - under [canoe/steel](https://github.com/Layr-Labs/hokulea/blob/3599bbeb855156164643a2a56c4f92de0cf7b7cf/crates/proof/Cargo.toml#L44) feature.
   - Requires installing the Risc0 toolchain, see [rzup](https://dev.risczero.com/api/zkvm/install).
2. Sp1-contract-call(Succinct)
   - under [canoe/sp1-cc](https://github.com/Layr-Labs/hokulea/blob/3599bbeb855156164643a2a56c4f92de0cf7b7cf/crates/proof/Cargo.toml#L45) feature.
   - Requires installing Sp1 toolchain, see [sp1up](https://docs.succinct.xyz/docs/sp1/getting-started/install).

Trying to build the hokulea client binary with either zkvm backend feature will fail if the respective toolchain is not installed.

### Running the example preloaded client with Steel or Sp1-contract-call
```bash
cd example/preloader
just run-preloader .devnet.env
```

More information at [./example/preloader/README.md](./example/preloader/README.md)

### If you are interested in looking at the dependancy graph of crates
```bash
just generate-deps-graphviz
```

## Run Against Sepolia

You will need to run an instance of [eigenda-proxy](https://github.com/Layr-Labs/eigenda-proxy) with V2 support. Then populate the `.sepolia.env` file, see a template at `.example.env`.

```bash
# To download a `sepolia.rollup.json` from a rollup consensus node, you can use the command
cast rpc "optimism_rollupConfig" --rpc-url $ROLLUP_NODE_RPC | jq > sepolia.rollup.json
# Before running the client, it will download the needed g1.point SRS file
# and the rollup.json config file. Temporary env variables are stored at
# .sepolia.env and .run.sepolia.env
# No need to fill L1_CONFIG_PATH as sepolia can be inferred from l2 rollup config
just run-client-against-sepolia 'native'
```

![](./assets/hokulea.jpeg)
