use alloy_primitives::{address, b256, keccak256, Address, B256};
use canoe_bindings::{Journal, StatusCode};
use canoe_provider::{CanoeInput, CertVerifierCall};
use canoe_steel_methods::CERT_VERIFICATION_ELF;
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    Contract,
};
use risc0_zkvm::{default_executor, ExecutorEnv, ExitCode};

const HEAD_NUMBER: u64 = 12_109_137;
const HEAD_TIMESTAMP: u64 = 1_794_368_376;
const HEAD_HASH: B256 = b256!("c00bb482113d9fd6578d356c391570f6830561ecb0603221e68ce55493909413");
const VERIFIER: Address = address!("17ec4112c4bbd540e2c1fe0a49d264a280176f0d");
const CONFIG_HASH: B256 = b256!("25752560bfc87e1f3466374640fd492f772ac436624c3948c375d890b4c51157");
const JOURNAL_KECCAK: B256 =
    b256!("d00d65b003d6ec22e8149bde987795cb843463b118d08b37d1ebc562e44afef9");
const RLP_LENGTHS: [usize; 5] = [870, 869, 868, 870, 870];
const RLP_KECCAKS: [B256; 5] = [
    b256!("7eb667de5a1716ce1d6c6a3e6ecfd0630e6e2af55691c03da099964e90fc7dbe"),
    b256!("1727491e81696cf163fadb1491e63ee8476ccc23d93aa5fcdf12ad78794d9cb8"),
    b256!("82e359113415cda9191a275d32b713b60fbacf162870fe6bc2b2b02037a8ee5b"),
    b256!("bf952bd72c77fec6b0c3f77ea702fa8d284f6744f70bd65487ecba61b691774f"),
    b256!("eb62fb1585023451f2a4047d6a984a9e9a31459f6d7e31f8542efad3ea130d81"),
];

fn held_inputs() -> (EthEvmInput, Vec<CanoeInput>) {
    let evm_input = bincode::deserialize(include_bytes!(
        "../../verifier/tests/fixtures/sepolia-12109137-evm-input.bin"
    ))
    .expect("decode held production Steel input");
    let canoe_inputs =
        bincode::deserialize(include_bytes!("fixtures/sepolia-12109137-canoe-inputs.bin"))
            .expect("decode held production certificate inputs");
    (evm_input, canoe_inputs)
}

fn expected_journals(canoe_inputs: &[CanoeInput]) -> Vec<u8> {
    assert_eq!(canoe_inputs.len(), RLP_KECCAKS.len());
    let journals: Vec<_> = canoe_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let rlp = input.altda_commitment.to_rlp_bytes();
            assert_eq!(input.l1_chain_id, 11_155_111);
            assert_eq!(input.l1_head_block_number, HEAD_NUMBER);
            assert_eq!(input.l1_head_block_hash, HEAD_HASH);
            assert_eq!(input.verifier_address, VERIFIER);
            assert!(input.claimed_validity);
            assert_eq!(rlp.len(), RLP_LENGTHS[index]);
            assert_eq!(keccak256(&rlp), RLP_KECCAKS[index]);
            Journal {
                blockNumber: HEAD_NUMBER,
                blockhash: HEAD_HASH,
                certVerifierAddress: VERIFIER,
                input: rlp.into(),
                output: true,
                l1ChainId: 11_155_111,
                chainConfigHash: CONFIG_HASH,
                chainSpecHash: B256::ZERO,
            }
        })
        .collect();
    let bytes = bincode::serialize(&journals).expect("serialize expected journals");
    assert_eq!(bytes.len(), 5_220);
    assert_eq!(keccak256(&bytes), JOURNAL_KECCAK);
    bytes
}

#[test]
fn held_production_contract_calls_match_claims_and_journals() {
    let (evm_input, canoe_inputs) = held_inputs();
    let expected = expected_journals(&canoe_inputs);
    let env = evm_input.into_env(&ETH_SEPOLIA_CHAIN_SPEC);

    assert_eq!(env.header().number, HEAD_NUMBER);
    assert_eq!(env.header().timestamp, HEAD_TIMESTAMP);
    assert_eq!(env.header().seal(), HEAD_HASH);
    assert_eq!(
        ETH_SEPOLIA_CHAIN_SPEC
            .active_fork(HEAD_NUMBER, HEAD_TIMESTAMP)
            .expect("held head has an active Steel fork")
            .to_string(),
        "Amsterdam"
    );
    assert_eq!(keccak256("Amsterdam"), CONFIG_HASH);

    let actual: Vec<_> = canoe_inputs
        .iter()
        .map(|input| {
            let is_valid = match CertVerifierCall::build(&input.altda_commitment) {
                CertVerifierCall::ABIEncodeInterface(call) => {
                    Contract::new(input.verifier_address, &env)
                        .call_builder(&call)
                        .call()
                        == StatusCode::SUCCESS as u8
                }
            };
            assert_eq!(is_valid, input.claimed_validity);
            Journal {
                blockNumber: HEAD_NUMBER,
                blockhash: HEAD_HASH,
                certVerifierAddress: input.verifier_address,
                input: input.altda_commitment.to_rlp_bytes().into(),
                output: is_valid,
                l1ChainId: input.l1_chain_id,
                chainConfigHash: CONFIG_HASH,
                chainSpecHash: B256::ZERO,
            }
        })
        .collect();
    let actual = bincode::serialize(&actual).expect("serialize actual journals");
    assert_eq!(actual, expected);
}

#[test]
#[ignore = "run only after the separate native contract phase is accepted"]
fn held_production_guest_commits_expected_journals() {
    let (evm_input, canoe_inputs) = held_inputs();
    let expected = expected_journals(&canoe_inputs);
    let executor_env = ExecutorEnv::builder()
        .write(&evm_input)
        .expect("write held Steel input")
        .write(&canoe_inputs)
        .expect("write held certificate inputs")
        .build()
        .expect("build executor environment");
    let session = default_executor()
        .execute(executor_env, CERT_VERIFICATION_ELF)
        .expect("execute production certificate-verification guest");

    assert_eq!(session.exit_code, ExitCode::Halted(0));
    assert_eq!(session.journal.bytes, expected);
}
