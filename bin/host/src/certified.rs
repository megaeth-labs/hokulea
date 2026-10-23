//! Serves `mega-certified-payload` hints from the block certifier's GET endpoint.
//!
//! The certifier is not trusted: a retrieved payload is encoded, held to the width and the KZG
//! point of the certificate the batch inbox accepted, and only then stored together with the
//! proof the client checks again. Bytes that fail any check are never stored.

use alloy_primitives::{hex, keccak256, FixedBytes, B256};
use anyhow::{anyhow, ensure, Result};
use eigenda_cert::CertifiedCommitment;
use hokulea_compute_proof::compute_kzg_commitment_and_proof;
use hokulea_eigenda::{EncodedPayload, BYTES_PER_FIELD_ELEMENT};
use kona_host::SharedKeyValueStore;
use kona_preimage::{PreimageKey, PreimageKeyType};
use reqwest::Url;
use std::time::Duration;
use tracing::{info, warn};

/// The largest payload a certified commitment can name: EigenDA's largest blob, 2^19 field
/// elements, less the header element, at 31 payload bytes each. op-alt-da's `MaxInputSize`.
pub const MAX_CERTIFIED_PAYLOAD_BYTES: usize = 16_252_897;

const DEFAULT_ATTEMPTS: u32 = 3;
const DEFAULT_BACKOFF: Duration = Duration::from_millis(500);

/// Fetches certified payloads from the block certifier's alt-DA server.
#[derive(Debug, Clone)]
pub struct CertifierClient {
    base: Url,
    inner: reqwest::Client,
    attempts: u32,
    backoff: Duration,
}

/// A certified encoded payload that matches its certificate, with the KZG proof binding it to
/// the certificate's blob point.
#[derive(Debug, Clone)]
pub struct VerifiedCertifiedPayload {
    /// The encoded payload of the retrieved payload.
    pub encoded_payload: EncodedPayload,
    /// `x || y` of the blob proof, 32 bytes big-endian each.
    pub kzg_proof: FixedBytes<64>,
}

impl CertifierClient {
    /// A client of the certifier server at `base`, retrying a failed retrieval a few times.
    pub fn new(base: Url) -> Self {
        Self {
            base,
            inner: reqwest::Client::new(),
            attempts: DEFAULT_ATTEMPTS,
            backoff: DEFAULT_BACKOFF,
        }
    }

    /// Retrieves the payload `commitment` names and holds it to the certificate: its encoding
    /// must be as wide as the blob and commit to the blob's point.
    pub async fn fetch_verified(
        &self,
        commitment: &CertifiedCommitment,
        l1_inclusion_block_number: u64,
    ) -> Result<VerifiedCertifiedPayload> {
        let payload = self
            .get_payload(commitment, l1_inclusion_block_number)
            .await?;
        let encoded_payload = EncodedPayload::encode(&payload)?;

        // The width costs nothing, the commitment an FFT and an MSM over the retrieved bytes.
        let blob = commitment.blob();
        ensure!(
            encoded_payload.num_field_element() == u64::from(blob.length),
            "certified payload encodes to {} field elements, but the certificate names {}",
            encoded_payload.num_field_element(),
            blob.length
        );
        let (point, kzg_proof) = compute_kzg_commitment_and_proof(encoded_payload.serialize())
            .map_err(|e| anyhow!("failed to commit to the certified payload: {e}"))?;
        let mut expected = FixedBytes::<64>::ZERO;
        expected[..32].copy_from_slice(&blob.commitment.x.to_be_bytes::<32>());
        expected[32..].copy_from_slice(&blob.commitment.y.to_be_bytes::<32>());
        ensure!(
            point == expected,
            "certified payload commits to {point}, but the certificate names {expected}"
        );

        Ok(VerifiedCertifiedPayload {
            encoded_payload,
            kzg_proof,
        })
    }

    /// `GET {certifier}/get/0x80{body}?l1_inclusion_block_number=N`, retried on failure.
    async fn get_payload(
        &self,
        commitment: &CertifiedCommitment,
        l1_inclusion_block_number: u64,
    ) -> Result<Vec<u8>> {
        let mut url = Url::parse(&format!(
            "{}/get/0x{}",
            self.base.as_str().trim_end_matches('/'),
            hex::encode(commitment.retrieval_key())
        ))?;
        url.query_pairs_mut().append_pair(
            "l1_inclusion_block_number",
            &l1_inclusion_block_number.to_string(),
        );

        let mut attempt = 1;
        loop {
            match self.get_payload_once(&url).await {
                Ok(payload) => return Ok(payload),
                Err(e) if attempt < self.attempts => {
                    warn!(target: "hokulea-host", "certified payload retrieval attempt {attempt} failed: {e}");
                    tokio::time::sleep(self.backoff * attempt).await;
                    attempt += 1;
                }
                Err(e) => {
                    return Err(e.context(format!(
                        "certified payload retrieval failed after {attempt} attempts"
                    )))
                }
            }
        }
    }

    /// One retrieval, reading at most [MAX_CERTIFIED_PAYLOAD_BYTES]: a larger body cannot be a
    /// certified payload, and reading it would only let the server exhaust the host's memory.
    async fn get_payload_once(&self, url: &Url) -> Result<Vec<u8>> {
        let mut response = self.inner.get(url.clone()).send().await?;
        ensure!(
            response.status().is_success(),
            "certifier responded {}",
            response.status()
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length <= MAX_CERTIFIED_PAYLOAD_BYTES as u64,
                "certifier announced a {length}-byte payload, over {MAX_CERTIFIED_PAYLOAD_BYTES}"
            );
        }
        let mut payload = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                payload.len() + chunk.len() <= MAX_CERTIFIED_PAYLOAD_BYTES,
                "certifier sent more than {MAX_CERTIFIED_PAYLOAD_BYTES} bytes"
            );
            payload.extend_from_slice(&chunk);
        }
        Ok(payload)
    }
}

/// Serves a `mega-certified-payload` hint: stores the verified encoded payload field element by
/// field element under `CertifiedCommitment::field_element_key`, and its KZG proof under
/// `CertifiedCommitment::kzg_proof_key`. On any error nothing is stored, and the kona host
/// backend retries the hint.
pub async fn fetch_certified_payload_hint(
    hint_data: &[u8],
    certifier: &CertifierClient,
    kv: SharedKeyValueStore,
) -> Result<()> {
    let (commitment, l1_inclusion_block_number) = CertifiedCommitment::from_payload_hint(hint_data)
        .map_err(|e| anyhow!("malformed certified payload hint: {e}"))?;
    let verified = certifier
        .fetch_verified(&commitment, l1_inclusion_block_number)
        .await?;

    let mut kv = kv.write().await;
    let field_elements = verified
        .encoded_payload
        .serialize()
        .chunks_exact(BYTES_PER_FIELD_ELEMENT);
    for (index, field_element) in field_elements.enumerate() {
        kv.set(
            global_generic_key(&commitment.field_element_key(index as u64)),
            field_element.to_vec(),
        )?;
    }
    kv.set(
        global_generic_key(&commitment.kzg_proof_key()),
        verified.kzg_proof.to_vec(),
    )?;

    info!(
        target: "hokulea-host",
        "stored certified payload of {} field elements for l1 block {l1_inclusion_block_number}",
        verified.encoded_payload.num_field_element()
    );
    Ok(())
}

fn global_generic_key(key_template: &[u8; 80]) -> B256 {
    PreimageKey::new(*keccak256(key_template), PreimageKeyType::GlobalGeneric).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use eigenda_cert::certified::test_utils::certified_calldata;
    use eigenda_cert::G1Point;
    use hokulea_eigenda::EigenDAPreimageProvider;
    use hokulea_proof::eigenda_provider::OracleEigenDAPreimageProvider;
    use hokulea_proof::errors::HokuleaOracleProviderError;
    use hokulea_proof::preloaded_eigenda_provider::batch_verify;
    use kona_host::MemoryKeyValueStore;
    use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
    use kona_preimage::{HintWriterClient, PreimageOracleClient};
    use rust_kzg_bn254_primitives::blob::Blob;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    /// A payload of a real EigenDA dispersal, and the blob point its certificate carried.
    const PAYLOAD: &str = "block-certifier eigenda smoke 1790059466";
    const POINT_X: &str = "1cfc201448ba83ceabd0dc0028825f9ba1e056e786120c3c165afe2672b9e1ed";
    const POINT_Y: &str = "0df0b0aac065c8bc3679aef9d5cf5c2ec5cec49684c9d819f6084807af9814d4";
    /// Another dispersal of the same width, so only the point tells the two apart.
    const OTHER_PAYLOAD: &str = "block-certifier eigenda cert fixture v1";

    fn point() -> G1Point {
        G1Point {
            x: U256::from_be_slice(&hex::decode(POINT_X).unwrap()),
            y: U256::from_be_slice(&hex::decode(POINT_Y).unwrap()),
        }
    }

    fn commitment() -> CertifiedCommitment {
        CertifiedCommitment::from_calldata(&certified_calldata(point(), 4)).unwrap()
    }

    #[derive(Clone)]
    struct Response {
        status: u16,
        body: Vec<u8>,
        content_length: bool,
    }

    impl Response {
        fn ok(body: &[u8]) -> Self {
            Self {
                status: 200,
                body: body.to_vec(),
                content_length: true,
            }
        }
    }

    /// A one-route HTTP/1.1 server answering every request with `response`, recording each
    /// request target.
    async fn fake_certifier(response: Response) -> (CertifierClient, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8; 1];
                    if stream.read(&mut byte).await.unwrap() == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                recorded.lock().unwrap().push(target);

                let mut reply = format!(
                    "HTTP/1.1 {} STATUS\r\nConnection: close\r\n",
                    response.status
                );
                if response.content_length {
                    reply += &format!("Content-Length: {}\r\n", response.body.len());
                }
                reply += "\r\n";
                // The client may hang up once it has seen enough, so write errors are expected.
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.write_all(&response.body).await;
                let _ = stream.shutdown().await;
            }
        });
        let mut client = CertifierClient::new(base);
        client.backoff = Duration::ZERO;
        (client, requests)
    }

    fn memory_kv() -> SharedKeyValueStore {
        Arc::new(RwLock::new(MemoryKeyValueStore::new()))
    }

    async fn stored(kv: &SharedKeyValueStore, key_template: &[u8; 80]) -> Option<Vec<u8>> {
        kv.read().await.get(global_generic_key(key_template))
    }

    async fn nothing_stored(kv: &SharedKeyValueStore, commitment: &CertifiedCommitment) -> bool {
        for index in 0..8 {
            if stored(kv, &commitment.field_element_key(index))
                .await
                .is_some()
            {
                return false;
            }
        }
        stored(kv, &commitment.kzg_proof_key()).await.is_none()
    }

    #[tokio::test]
    async fn good_payload_is_verified_and_stored() {
        let (certifier, requests) = fake_certifier(Response::ok(PAYLOAD.as_bytes())).await;
        let commitment = commitment();
        let kv = memory_kv();

        fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
            .await
            .unwrap();

        assert_eq!(
            *requests.lock().unwrap(),
            vec![format!(
                "/get/0x80{}?l1_inclusion_block_number=77",
                hex::encode(commitment.body())
            )]
        );
        let encoded = EncodedPayload::encode(PAYLOAD.as_bytes()).unwrap();
        let mut served = Vec::new();
        for index in 0..4 {
            served.extend(
                stored(&kv, &commitment.field_element_key(index))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(served, encoded.serialize().to_vec());
        assert!(stored(&kv, &commitment.field_element_key(4))
            .await
            .is_none());

        let proof = stored(&kv, &commitment.kzg_proof_key()).await.unwrap();
        assert!(batch_verify(
            &[Blob::new(&served).unwrap()],
            &[point()],
            &[FixedBytes::from_slice(&proof)]
        ));
    }

    #[tokio::test]
    async fn payload_for_another_point_is_not_stored() {
        let (certifier, _) = fake_certifier(Response::ok(OTHER_PAYLOAD.as_bytes())).await;
        let commitment = commitment();
        let kv = memory_kv();

        let err =
            fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
                .await
                .unwrap_err();
        assert!(err.to_string().contains("commits to"), "{err}");
        assert!(nothing_stored(&kv, &commitment).await);
    }

    #[tokio::test]
    async fn payload_of_another_width_is_not_stored() {
        let (certifier, _) = fake_certifier(Response::ok(&[7u8; 200])).await;
        let commitment = commitment();
        let kv = memory_kv();

        let err =
            fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
                .await
                .unwrap_err();
        assert!(err.to_string().contains("field elements"), "{err}");
        assert!(nothing_stored(&kv, &commitment).await);
    }

    #[tokio::test]
    async fn oversize_payload_is_not_stored() {
        for content_length in [true, false] {
            let (certifier, _) = fake_certifier(Response {
                status: 200,
                body: vec![0u8; MAX_CERTIFIED_PAYLOAD_BYTES + 1],
                content_length,
            })
            .await;
            let commitment = commitment();
            let kv = memory_kv();

            let err =
                fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
                    .await
                    .unwrap_err();
            // An announced length is refused before the body is read, a streamed body once the
            // cap is crossed.
            let refusal = if content_length {
                "announced"
            } else {
                "sent more than"
            };
            let chain = format!("{err:#}");
            assert!(chain.contains(refusal), "{chain}");
            assert!(nothing_stored(&kv, &commitment).await);
        }
    }

    #[tokio::test]
    async fn http_error_is_retried_then_not_stored() {
        let (certifier, requests) = fake_certifier(Response {
            status: 500,
            body: b"boom".to_vec(),
            content_length: true,
        })
        .await;
        let commitment = commitment();
        let kv = memory_kv();

        let err =
            fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
                .await
                .unwrap_err();
        assert!(format!("{err:#}").contains("500"), "{err:#}");
        assert_eq!(requests.lock().unwrap().len(), DEFAULT_ATTEMPTS as usize);
        assert!(nothing_stored(&kv, &commitment).await);
    }

    /// A preimage oracle client over the host's key-value store, recording the hints it writes.
    #[derive(Clone)]
    struct KvOracle {
        kv: SharedKeyValueStore,
        hints: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl PreimageOracleClient for KvOracle {
        async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
            self.kv
                .read()
                .await
                .get(key.into())
                .ok_or(PreimageOracleError::KeyNotFound)
        }

        async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
            let value = self.get(key).await?;
            if value.len() != buf.len() {
                return Err(PreimageOracleError::BufferLengthMismatch(
                    buf.len(),
                    value.len(),
                ));
            }
            buf.copy_from_slice(&value);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl HintWriterClient for KvOracle {
        async fn write(&self, hint: &str) -> PreimageOracleResult<()> {
            self.hints.lock().unwrap().push(hint.to_string());
            Ok(())
        }
    }

    /// The client provider reads back what the hint handler stored, under the hint it writes,
    /// and refuses stored bytes the proof does not bind to the certificate.
    #[tokio::test]
    async fn client_reads_what_the_host_stored() {
        let (certifier, _) = fake_certifier(Response::ok(PAYLOAD.as_bytes())).await;
        let commitment = commitment();
        let kv = memory_kv();
        fetch_certified_payload_hint(&commitment.payload_hint(77), &certifier, kv.clone())
            .await
            .unwrap();

        let oracle = KvOracle {
            kv: kv.clone(),
            hints: Arc::default(),
        };
        let mut client = OracleEigenDAPreimageProvider::new(Arc::new(oracle.clone()));
        let encoded = client
            .get_certified_encoded_payload(&commitment, 77)
            .await
            .unwrap();
        assert_eq!(encoded, EncodedPayload::encode(PAYLOAD.as_bytes()).unwrap());
        assert_eq!(
            *oracle.hints.lock().unwrap(),
            vec![format!(
                "mega-certified-payload {}",
                hex::encode(commitment.payload_hint(77))
            )]
        );

        let key = global_generic_key(&commitment.field_element_key(1));
        let mut field_element = kv.read().await.get(key).unwrap();
        field_element[31] ^= 1;
        kv.write().await.set(key, field_element).unwrap();
        let err = client
            .get_certified_encoded_payload(&commitment, 77)
            .await
            .unwrap_err();
        assert!(
            matches!(err, HokuleaOracleProviderError::UnboundCertifiedPayload),
            "{err}"
        );
    }

    #[tokio::test]
    async fn malformed_hint_is_refused_without_retrieval() {
        let (certifier, requests) = fake_certifier(Response::ok(PAYLOAD.as_bytes())).await;
        let hint = commitment().payload_hint(77);
        let kv = memory_kv();

        assert!(
            fetch_certified_payload_hint(&hint[1..], &certifier, kv.clone())
                .await
                .is_err()
        );
        assert!(requests.lock().unwrap().is_empty());
    }
}
