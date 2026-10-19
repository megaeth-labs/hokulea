//! An implementation of the [EigenDAPreimageProvider] trait for tests.

use crate::errors::HokuleaErrorKind;
use crate::{EigenDAPreimageProvider, EncodedPayload};
use alloc::vec::Vec;
use alloy_primitives::{map::HashMap, Bytes, B256};
use eigenda_cert::{AltDACommitment, CertifiedCommitment};

use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;

/// Custom hokulea preimage error
#[derive(Debug, Clone, thiserror::Error)]
pub enum TestHokuleaProviderError {
    /// Preimage Oracle error from kona
    /// <https://github.com/op-rs/kona/blob/174b2ac5ad3756d4469553c7777b04056f9d151c/crates/proof/proof/src/errors.rs#L18>
    #[error("Preimage oracle error")]
    Preimage,
    /// Critical Oracle error
    #[error("Critical error")]
    Critical,
}

impl From<TestHokuleaProviderError> for HokuleaErrorKind {
    fn from(val: TestHokuleaProviderError) -> Self {
        match val {
            // in kona, all Preimage error are grouped into backend error <https://github.com/op-rs/kona/blob/4ef01882824b84d078ead9f834f4f78213dd6ef3/crates/protocol/derive/src/sources/blobs.rs#L136>
            // which is considered a temp issue
            TestHokuleaProviderError::Preimage => {
                HokuleaErrorKind::Temporary("Preimage temporary error".to_string())
            }
            TestHokuleaProviderError::Critical => {
                HokuleaErrorKind::Critical("Critical error".to_string())
            }
        }
    }
}

// a mock object implements the EigenDAPreimageProvider trait
#[derive(Debug, Clone, Default)]
pub(crate) struct TestEigenDAPreimageProvider {
    pub validities: HashMap<B256, Result<bool, TestHokuleaProviderError>>,
    pub encoded_payloads: HashMap<B256, Result<EncodedPayload, TestHokuleaProviderError>>,
    // certified encoded payloads keyed by commitment body
    pub certified_payloads: HashMap<Bytes, Result<EncodedPayload, TestHokuleaProviderError>>,
    // every certified request served, with its l1 inclusion block number
    pub certified_requests: Vec<(Bytes, u64)>,
    // a backend error propogated to the client
    pub should_preimage_err: bool,
}

impl TestEigenDAPreimageProvider {
    pub(crate) fn insert_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
        validity: Result<bool, TestHokuleaProviderError>,
    ) {
        self.validities
            .insert(altda_commitment.to_digest(), validity);
    }

    pub(crate) fn insert_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
        encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
    ) {
        self.encoded_payloads
            .insert(altda_commitment.to_digest(), encoded_payload);
    }

    pub(crate) fn insert_certified_payload(
        &mut self,
        commitment: &CertifiedCommitment,
        encoded_payload: Result<EncodedPayload, TestHokuleaProviderError>,
    ) {
        self.certified_payloads
            .insert(commitment.body().clone(), encoded_payload);
    }
}

#[async_trait]
impl EigenDAPreimageProvider for TestEigenDAPreimageProvider {
    type Error = TestHokuleaProviderError;

    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error> {
        if self.should_preimage_err {
            return Err(TestHokuleaProviderError::Preimage);
        }

        self.validities
            .get(&altda_commitment.to_digest())
            .unwrap()
            .clone()
    }

    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error> {
        if self.should_preimage_err {
            return Err(TestHokuleaProviderError::Preimage);
        }

        self.encoded_payloads
            .get(&altda_commitment.to_digest())
            .unwrap()
            .clone()
    }

    async fn get_certified_encoded_payload(
        &mut self,
        commitment: &CertifiedCommitment,
        l1_inclusion_block_number: u64,
    ) -> Result<EncodedPayload, Self::Error> {
        self.certified_requests
            .push((commitment.body().clone(), l1_inclusion_block_number));
        self.certified_payloads
            .get(commitment.body())
            .unwrap()
            .clone()
    }
}
