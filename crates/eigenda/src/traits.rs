use crate::{errors::HokuleaErrorKind, EncodedPayload};
use alloc::{boxed::Box, string::ToString};
use async_trait::async_trait;
use core::fmt::Display;
use eigenda_cert::{AltDACommitment, CertifiedCommitment};

/// This traits defines functions to access preimage oracle for EigenDA blob derivation. See
/// <https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#derivation-process>
#[async_trait]
pub trait EigenDAPreimageProvider {
    /// The error type for the [EigenDAPreimageProvider].
    type Error: Display + ToString + Into<HokuleaErrorKind>;

    /// Fetch preimage about the validity of a DA cert. Return generic preimage error. Return false when
    /// DA cert is valid if the DA network attestation is correct and offchain derivation version is
    /// consistent to the one stored on L1 contract
    async fn get_validity(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<bool, Self::Error>;

    /// Fetch the encoded payloads from the altda commitment
    /// The encoded payload size is always a power of 2, with a minimum of 32 bytes.
    /// (e.g., 32, 64, 128, 256, 512, ... bytes)
    async fn get_encoded_payload(
        &mut self,
        altda_commitment: &AltDACommitment,
    ) -> Result<EncodedPayload, Self::Error>;

    /// Fetch the encoded payload a certified commitment names, retrieved from the block
    /// certifier at `l1_inclusion_block_number`, the L1 block that included the commitment.
    ///
    /// Implementations must return only an encoded payload whose KZG commitment, in evaluation
    /// form, is the certificate's blob point (`commitment.blob().commitment`): the caller checks
    /// the width and the encoding, but holds no SRS. A certified commitment has no validity or
    /// recency query, because the inbox accepting it is its validity.
    async fn get_certified_encoded_payload(
        &mut self,
        commitment: &CertifiedCommitment,
        l1_inclusion_block_number: u64,
    ) -> Result<EncodedPayload, Self::Error>;
}

/// The index where INTERFACE_BYTE is located
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_EIGENDA_API_BYTE_INDEX: usize = 32;

/// In the address space of preimage oracle, the validity corresponds to both 1. the validity of da cert
/// and 2. the validity of consistent derivation version being used in DA cert and in the certVerifier
/// routed according to the reference block number
/// More see <https://github.com/Layr-Labs/hokulea/tree/master/docs#reserved-addresses-for-da-certificates>
pub const RESERVED_EIGENDA_API_BYTE_FOR_VALIDITY: u8 = 1;
