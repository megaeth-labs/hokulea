use risc0_steel::ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC};

#[test]
fn direct_guest_lock_decodes_held_post_glamsterdam_input() {
    let bytes = include_bytes!("../../../verifier/tests/fixtures/sepolia-12109137-evm-input.bin");
    let input: EthEvmInput = bincode::deserialize(bytes).expect(
        "the independently locked direct guest dependency must decode the held production input",
    );
    assert_eq!(bincode::serialize(&input).unwrap(), bytes);
    let env = input.into_env(&ETH_SEPOLIA_CHAIN_SPEC);
    assert_eq!(env.header().number, 12_109_137);
    assert_eq!(env.header().timestamp, 1_794_368_376);
    assert_eq!(env.header().inner().inner().slot_number, Some(11_552_898));
    assert_eq!(
        format!("{:#x}", env.header().seal()),
        "0xc00bb482113d9fd6578d356c391570f6830561ecb0603221e68ce55493909413"
    );
}
