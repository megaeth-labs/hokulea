//! Regression coverage for the complete L1-header boundary used by Canoe witness generation.
use alloy_primitives::{address, b256, hex, Address, B256};
use async_trait::async_trait;
use canoe_provider::{CanoeInput, CanoeProvider};
use eigenda_cert::AltDACommitment;
use hokulea_proof::eigenda_witness::EigenDAPreimage;
use hokulea_witgen::from_boot_info_to_canoe_proof;
use kona_preimage::{errors::PreimageOracleResult, PreimageKey, PreimageOracleClient};
use kona_proof::BootInfo;
use std::sync::{Arc, Mutex};

const OLD: &[u8] = &hex!("f9026da0b5a16d1c6d328caf114ba4672a826f64363a91cc1834e0a66da695314ea0709da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479421a0f7be1b1904b8d23d40d363d9fa97b6082b8fa0269dcae3a7b23c3dc754b5cba894e71e6dcbd3e0c73a23963f086fbe1a1b22b9a0b7e3c97e6e6446de93c0ca2ffffaff0d329d51f36cb8366e1c15001c18d0ba68a0954e5621265429bcf260e266250a06a5587bbac5f6cb15bdec78244c963e795db90100d6bb4d2028721098f10cd225a6333084450c11c23507283090ad2b1850a4180a39038300b4c8f5ac61d796076c338522a381a8511e6630565ebc400caca764efc216b0688a3128b95c402f48418ac3b00007031858ee093f200128979a401c0ffda2c400c223d2b0b2411ccecaa41930cf43b06a080f2e08383484143deb2d7c4090014b00c481adc14902700073408b4c71a1c1a57acd0c8034505618b9503c0340514b0dc8a4941e98cb8219508ad03767d8079511863e80071eb46fd5a5f47f653a226c1218651614869400394a0650832a71506d8ed605579d172d20e047b3553ca0159e0062707628b631c46d4a9f0c40004cb9454448a95a11624771a2808401913cc2840393870083c7cf32846ae2b2e380a03c7f04ab77b4062e250a149dc491f8144b15ea0e4e6f5b4d093b24440333e8a6880000000000000000840539aa8aa0bd6ec2f0afe10b74f8d32255a9cd511a876e2ef8fa85356a3a588386bf88df8f83120000840ad47767a0af46c2acb033059d5f22d675e02917bc3c85be3afbb18c2d5701513ee2f5bdd4a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
const NEW: &[u8] = &hex!("f902a2a06af9aad934e75cf5e78bd0ca7c44052158e6612b3917b71747890a937a7ea7aca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794421df94fe5cb177c666df6402e7de7d368319ec3a0e5e78bfb1e6abc124f114efb27ecad4477539a14a70bfc5e233ec6e9c336f07aa0695d20b2fa7f18174df430cd669af1bb483f5a7b224ee658bdf7708996421d34a02b0ff288aa87ce68ef300bf54659b9a40e2e916010cc430458cc46940a554d44b901002eb96f4dfad683dc9bcba878c715ba5d33da63ddd3d0e6bf5199164e6f2e85ce69b95b5a06a3f6643bb2477be5a144bd620f890cc6f7e97f464b0f8bbeecfdaed914db410b89c73c6d9843fec07924a1ba5f8e7c33a679d80ea927ffbee3d798efd210b272fde46bbf72a850df6a1f597eb2734b77ec16003e3355d3b4ac30fa4ffb9ab11b9e7af8f3b2db5deb6218b6297c0fa3a4337c6d5c2591de66475e38caeaf636147c60cb3e586be6b419e1a7538f734925940b8ef1f6dab1b6bbcb59680d85c33f9a3a59ebcf640effcaceb9ddf2886faeac497538b19700f2b4694ae6d7bf5b54a37ade9b1578833f6178fdabee9b869d950868abceeaa21a0b52ef8083b8b411840bebbf0484046a8e10846af3123895726275696c6465722e6d6967616c6162732e657468a02fab8d9a39329ac25d72841db303973d9161d4adfb6a3e476043f9324b2eecfd88000000000000000016a0fa91cc9baec3f4ff701da617053711ba9768d631a7dfe6dfaea48531cd92bd1f831000008388aa8da018bc22824857259aa369cc3a7b0c90c0b83728d7d08382699fbfbaa909789cc4a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a0455f75c08294a2ba862f00d30bc58d65f9cf073a9b4cee805eadc06623734f8d83b03712");
const CERT: &[u8] = &hex!("010002f9035ee5a0003ba95de6469b8a829d027445df4806a640976abc219e8cc783eb4a7a3e053683b8b2daf901ccf901c7f9017f8001f90159f842a0248a8d4614591729b9e901914b2a03caeea40e1d89f3b8e53a6bd55e5959f831a02c15e67e574a9ad7e07b9dc4a05a0ecefac288ce014f1ad7c28deedfeb62db4af886f8409f0d915cb4f84cc1a350fae9677e58a9378a481969d99a75a8cc5f176d906e659fd3b2076c420d7199e3218528a773576f5c448936c157bc677fe28b559d5bf9f842a022eeb443fb51a0e65795126db44cddb31056ac14c8712539967aa4e32d9212bba028557f43ed6fe1e82da208f5b8927fbae50b261acd4ed18340abb2129ad286eff888f842a0137cccdf3c73acfc53b76b9a27f8bde6b7b73ce13853ff2c9b442678ef6e411ea012d50ad2823121877abe18deb4a76618fa9fb181a913580c1b12edd96d8b21ebf842a0079bd8c510b2604d3051a530a64ae1a5bb2598c45b7e6f49433f63e9a770479ea020d2a17f07a4af6d8ccd3c05981821f19178c775a3fbdab71238b25ab2b1996f828000a0d2804bef3936fd7a3e61997489ddd3a5d5cce13ef8f6fa5bd1dc1e7c09f98441b8411d97fd4c6f8dbaabe5515c9e84f0c459ccfb5c0b7dd4c1c363878e8448d87a4539373186949097280d79a40fc83d763fff49fc34e77f0dacca8fb2c5cfb3d94000c1808080f90163c0c0f888f842a02099209289cdb7e5087d0401996d2fd9b52ce5cae39c547a039f126371a7f9bca026139d9d30188c9d52468ce9dfb48c39d552243611d5b270f5497c2b8692c696f842a02b2dabbf32c0cb551d3ba9159ae5c985ebcd71d79b00fabd26a74d618065bfd6a01bef832bd3efaea9f61c0582fb123bb547546f0c5910a9dda96bcd0063d57a02f888f842a027b90b5da16ef02417ad5820223e680d2c2d19a3f1d30566cfbb7b9aa30abf6da022432d9b57d271b8dd84bfb4ccd9df36b84e422cb471b35d50d55ae83a03f16ef842a0018ed79d6c0707cc6f4ec81bcea6c4cc0096f0e3635961caf3271c3c9a36a9dfa0179360dc4646a7c49bf730e1789c00622facd7836faa3c747be0f2d824cb1412f842a026256828590b05c6906a920115e206ce6bc3c41208257ecd7695705c958c48a3a020393ac29ce28c7098122865037efb8d5900b56ce6faba91ce9973955d981570c20705c20805c2c0c0820001");
const OLD_HASH: B256 = b256!("1100d0de9f00856eb16cdf02285542ace7a1508c35202a75a05c2ae5040ac3fa");
const NEW_HASH: B256 = b256!("49482846ccac74bbd3820e234d0c0f8623edafb6075b771c12896d8e44668e53");
const VERIFIER: Address = address!("17ec4112c4bbd540e2c1fe0a49d264a280176f0d");

struct BoundOracle {
    head: B256,
    bytes: Vec<u8>,
}

#[async_trait]
impl PreimageOracleClient for BoundOracle {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        assert_eq!(key, PreimageKey::new_keccak256(*self.head));
        Ok(self.bytes.clone())
    }

    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        buf.copy_from_slice(&self.get(key).await?);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingProvider {
    calls: Arc<Mutex<Vec<Vec<CanoeInput>>>>,
    fail: bool,
}

#[async_trait]
impl CanoeProvider for RecordingProvider {
    type Receipt = u64;

    async fn create_certs_validity_proof(
        &self,
        inputs: Vec<CanoeInput>,
    ) -> Option<anyhow::Result<u64>> {
        let count = inputs.len();
        self.calls.lock().unwrap().push(inputs);
        if self.fail {
            Some(Err(anyhow::anyhow!("recording provider failure")))
        } else if count == 0 {
            None
        } else {
            Some(Ok(count as u64))
        }
    }
}

fn cert() -> AltDACommitment {
    AltDACommitment::try_from(CERT).unwrap()
}

fn boot(head: B256, chain: u64) -> BootInfo {
    BootInfo {
        l1_head: head,
        agreed_l2_output_root: B256::ZERO,
        claimed_l2_output_root: B256::ZERO,
        claimed_l2_block_number: 0,
        chain_id: 6343,
        rollup_config: kona_genesis::RollupConfig {
            l1_chain_id: chain,
            ..Default::default()
        },
        l1_config: Default::default(),
    }
}

async fn call(
    bytes: &[u8],
    head: B256,
    chain: u64,
    empty: bool,
    provider: RecordingProvider,
) -> anyhow::Result<Option<u64>> {
    let preimage = EigenDAPreimage {
        validities: if empty {
            vec![]
        } else {
            vec![(cert(), false), (cert(), true)]
        },
        ..Default::default()
    };
    from_boot_info_to_canoe_proof(
        &boot(head, chain),
        &preimage,
        &BoundOracle {
            head,
            bytes: bytes.to_vec(),
        },
        provider,
        VERIFIER,
    )
    .await
}

async fn positive(bytes: &[u8], head: B256, number: u64, chain: u64) {
    let provider = RecordingProvider::default();
    assert_eq!(
        call(bytes, head, chain, false, provider.clone())
            .await
            .unwrap(),
        Some(2)
    );
    let calls = provider.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].len(), 2);
    for (input, validity) in calls[0].iter().zip([false, true]) {
        assert_eq!(input.l1_head_block_hash, head);
        assert_eq!(input.l1_head_block_number, number);
        assert_eq!(input.l1_chain_id, chain);
        assert_eq!(input.verifier_address, VERIFIER);
        assert_eq!(input.claimed_validity, validity);
        assert_eq!(input.altda_commitment, cert());
    }
}

async fn rejected(bytes: &[u8], head: B256, expected: &str) {
    let provider = RecordingProvider::default();
    let error = call(bytes, head, 11155111, false, provider.clone())
        .await
        .expect_err("invalid header accepted");
    assert!(
        error.to_string().contains(expected),
        "unexpected error: {error}"
    );
    assert!(
        provider.calls.lock().unwrap().is_empty(),
        "invalid header reached provider"
    );
}

#[tokio::test]
async fn historical_header_preserves_inputs() {
    positive(OLD, OLD_HASH, 26295490, 1).await;
}

#[tokio::test]
async fn current_header_preserves_complete_inputs() {
    positive(NEW, NEW_HASH, 12104721, 11155111).await;
}

#[tokio::test]
async fn wrong_hash_stops_before_provider() {
    rejected(OLD, B256::ZERO, "hash mismatch").await;
}

#[tokio::test]
async fn truncated_or_trailing_bytes_stop_before_provider() {
    for (original, hash) in [(OLD, OLD_HASH), (NEW, NEW_HASH)] {
        rejected(&original[..original.len() - 1], hash, "cannot rlp decode").await;
        let mut trailing = original.to_vec();
        trailing.push(0);
        rejected(&trailing, hash, "cannot rlp decode").await;
    }
}

#[tokio::test]
async fn provider_error_is_preserved() {
    let provider = RecordingProvider {
        fail: true,
        ..Default::default()
    };
    assert_eq!(
        call(OLD, OLD_HASH, 1, false, provider.clone())
            .await
            .unwrap_err()
            .to_string(),
        "recording provider failure"
    );
    assert_eq!(provider.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn empty_input_remains_none_after_header_validation() {
    for (bytes, hash, chain) in [(OLD, OLD_HASH, 1), (NEW, NEW_HASH, 11155111)] {
        let provider = RecordingProvider::default();
        assert_eq!(
            call(bytes, hash, chain, true, provider.clone())
                .await
                .unwrap(),
            None
        );
        assert_eq!(provider.calls.lock().unwrap().len(), 1);
        assert!(provider.calls.lock().unwrap()[0].is_empty());
    }
}
