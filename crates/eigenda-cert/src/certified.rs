//! Certified batch commitments: the calldata a certified batcher transaction carries,
//! `0x01 0x80 || abi.encode(BatchCommitment)`, which the batch inbox decoded and verified before
//! it emitted the acceptance event that makes the transaction a certified item.
//!
//! Derivation reads two of the commitment's fields. The EigenDA certificate names the blob, and
//! `eigenda_commitment`, the keccak256 of the certificate's blob commitment, is the value the
//! certifier signed. The cursors and the signature were the inbox's business and are not checked
//! again here.
//!
//! Mirrors op-node's `certified_commitment.go` and `eigenda/cert.go`; the shared vector
//! `testdata/certified_calldata.json` is written by mega-block-certifier's Solidity.

use crate::G1Point;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes};
use alloy_sol_types::{sol, SolValue};
use serde::{Deserialize, Serialize};

/// Derivation version byte of every alt-DA batcher transaction.
pub const ALTDA_DERIVATION_VERSION: u8 = 0x01;

/// Commitment type the block certification spec allocates certified commitments, outside the OP
/// Stack reserved range `0x00..=0x7f`.
pub const CERTIFIED_COMMITMENT_TYPE: u8 = 0x80;

/// Byte length batch-inbox.md fixes for `BatchCommitment.certifierSig`. The ABI type is dynamic
/// `bytes`, so canonicality alone cannot enforce it.
pub const CERTIFIER_SIG_BYTES: usize = 65;

/// Preimage key domain byte for the field elements of a certified encoded payload. Sits where the
/// legacy keys carry `RESERVED_EIGENDA_API_BYTE_INDEX`, so the two key spaces stay apart even
/// before the digest separates them.
const FIELD_ELEMENT_KEY_DOMAIN: u8 = 0x80;

/// Preimage key domain byte for the KZG proof of a certified encoded payload.
const KZG_PROOF_KEY_DOMAIN: u8 = 0x81;

/// Index of the key domain byte inside an 80-byte preimage key template.
const KEY_DOMAIN_INDEX: usize = 32;

sol! {
    /// The inbox cursor a batch commitment moves from and to.
    #[derive(Debug, PartialEq, Eq)]
    struct CertifiedCursor {
        uint64 height;
        uint32 index;
        uint64 blockNumber;
        uint64 epochNum;
        bytes32 framesDigest;
        bytes32 quorumSnapshotHash;
    }

    /// The calldata layout of batch-inbox.md's BatchCommitment.
    #[derive(Debug, PartialEq, Eq)]
    struct BatchCommitment {
        bytes eigendaCert;
        bytes eigendaCommitment;
        CertifiedCursor prevCursor;
        CertifiedCursor cursor;
        bytes certifierSig;
    }
}

/// Why calldata or a hint is not a usable certified commitment. Every variant is a verdict about
/// the bytes alone, so no retrieval can change it.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedCommitmentError {
    /// The calldata does not open with `0x01 0x80`.
    #[error("calldata does not open with the certified prefix 0x0180")]
    NotCertifiedPrefix,
    /// The body is not an ABI encoding of a BatchCommitment.
    #[error("body is not an ABI encoding of BatchCommitment")]
    AbiDecode,
    /// The body decodes, but is not the encoding `abi.encode` writes for the decoded fields.
    #[error("body is not the canonical encoding of its own BatchCommitment")]
    NonCanonical,
    /// The certifier signature has the wrong length.
    #[error("certifier signature is {0} bytes, not 65")]
    CertifierSigLength(usize),
    /// `eigenda_cert` is not an ABI-encoded EigenDACertV3.
    #[error("eigenda_cert is not an ABI-encoded EigenDACertV3")]
    CertDecode,
    /// `eigenda_commitment` is not the digest of the certificate's blob commitment.
    #[error("eigenda_commitment does not match the certificate's blob commitment")]
    CommitmentMismatch,
    /// A payload hint is not `0x80 || body || l1_inclusion_block_number`.
    #[error("certified payload hint is malformed")]
    MalformedHint,
}

/// The certificate's `blobHeader.commitment`, in the two forms a payload is held to.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)] //
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)] //
pub struct AttestedBlob {
    /// The KZG commitment of the encoded payload in evaluation form.
    pub commitment: G1Point,
    /// The encoded payload's field element count.
    pub length: u32,
}

/// A certified batch commitment that decoded strictly and whose certificate is the attested one.
///
/// The body is retained because the certifier server keys its store by the whole submission, not
/// by the certificate: a retrieval has to ask for the bytes the batcher submitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)] //
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)] //
pub struct CertifiedCommitment {
    body: Bytes,
    blob: AttestedBlob,
}

impl CertifiedCommitment {
    /// Reads a certified batcher transaction's calldata, prefix included.
    pub fn from_calldata(calldata: &[u8]) -> Result<Self, CertifiedCommitmentError> {
        let body = calldata
            .strip_prefix(&[ALTDA_DERIVATION_VERSION, CERTIFIED_COMMITMENT_TYPE])
            .ok_or(CertifiedCommitmentError::NotCertifiedPrefix)?;
        Self::from_body(body)
    }

    /// Reads the ABI body of a certified commitment, the calldata without its two prefix bytes.
    pub fn from_body(body: &[u8]) -> Result<Self, CertifiedCommitmentError> {
        let decoded = decode_body(body)?;
        let blob = attested_blob(&decoded.eigendaCert, &decoded.eigendaCommitment)?;
        Ok(Self {
            body: Bytes::copy_from_slice(body),
            blob,
        })
    }

    /// The ABI body the batcher submitted.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The attested blob commitment a retrieved payload must match.
    pub fn blob(&self) -> &AttestedBlob {
        &self.blob
    }

    /// The certifier server's store key: `0x80 || body`. The GET path asks for exactly this.
    pub fn retrieval_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + self.body.len());
        key.push(CERTIFIED_COMMITMENT_TYPE);
        key.extend_from_slice(&self.body);
        key
    }

    /// The `mega-certified-payload` hint body: `0x80 || body || l1_inclusion_block_number`, the
    /// block number big-endian. The host needs the inclusion block for the certifier's GET query.
    pub fn payload_hint(&self, l1_inclusion_block_number: u64) -> Vec<u8> {
        let mut hint = self.retrieval_key();
        hint.extend_from_slice(&l1_inclusion_block_number.to_be_bytes());
        hint
    }

    /// Inverse of [Self::payload_hint].
    pub fn from_payload_hint(hint: &[u8]) -> Result<(Self, u64), CertifiedCommitmentError> {
        let (key, block_number) = hint
            .split_last_chunk::<8>()
            .ok_or(CertifiedCommitmentError::MalformedHint)?;
        let body = key
            .strip_prefix(&[CERTIFIED_COMMITMENT_TYPE])
            .ok_or(CertifiedCommitmentError::MalformedHint)?;
        Ok((Self::from_body(body)?, u64::from_be_bytes(*block_number)))
    }

    /// Preimage key template of the encoded payload's field element `index`.
    ///
    /// `| keccak256(retrieval key) | 0x80 | 0 .. 0 | index (8 bytes) |`, 80 bytes, the layout of
    /// `AltDACommitment::digest_template`. Keyed by the whole submission for the reason that one
    /// gives: two submissions can share a blob point.
    pub fn field_element_key(&self, index: u64) -> [u8; 80] {
        let mut key = self.key_template(FIELD_ELEMENT_KEY_DOMAIN);
        key[72..].copy_from_slice(&index.to_be_bytes());
        key
    }

    /// Preimage key template of the KZG proof binding the encoded payload to the blob commitment.
    pub fn kzg_proof_key(&self) -> [u8; 80] {
        self.key_template(KZG_PROOF_KEY_DOMAIN)
    }

    fn key_template(&self, domain: u8) -> [u8; 80] {
        let mut key = [0u8; 80];
        key[..32].copy_from_slice(keccak256(self.retrieval_key()).as_slice());
        key[KEY_DOMAIN_INDEX] = domain;
        key
    }
}

/// Strict decode: re-encoding must reproduce the body byte for byte, so two different calldata
/// cannot decode to the same commitment, and the signature must have its declared length.
fn decode_body(body: &[u8]) -> Result<BatchCommitment, CertifiedCommitmentError> {
    let decoded =
        BatchCommitment::abi_decode(body).map_err(|_| CertifiedCommitmentError::AbiDecode)?;
    if decoded.abi_encode() != body {
        return Err(CertifiedCommitmentError::NonCanonical);
    }
    // A wrong-length signature re-encodes to itself, so canonicality cannot see it.
    if decoded.certifierSig.len() != CERTIFIER_SIG_BYTES {
        return Err(CertifiedCommitmentError::CertifierSigLength(
            decoded.certifierSig.len(),
        ));
    }
    Ok(decoded)
}

/// Reads the certificate's blob commitment and holds it to the attestation:
/// `eigenda_commitment == keccak256(abi.encode(cert.blobInclusionInfo.blobCertificate.blobHeader.commitment))`.
///
/// The decode validates words the way op-node's go-ethereum `Unpack` does: a `uint16` or `uint32`
/// word with dirty high bits is refused, not truncated. Truncating would re-encode clean, so a
/// commitment op-node skips would match here. EigenDACertV3 holds no address, bool, short
/// `bytesN` or string, so alloy's validation checks nothing go-ethereum does not.
fn attested_blob(
    cert: &[u8],
    eigenda_commitment: &[u8],
) -> Result<AttestedBlob, CertifiedCommitmentError> {
    let cert = canoe_bindings::EigenDACertV3::abi_decode_validate(cert)
        .map_err(|_| CertifiedCommitmentError::CertDecode)?;
    let blob = cert.blobInclusionInfo.blobCertificate.blobHeader.commitment;
    if keccak256(blob.abi_encode()).as_slice() != eigenda_commitment {
        return Err(CertifiedCommitmentError::CommitmentMismatch);
    }
    Ok(AttestedBlob {
        commitment: G1Point {
            x: blob.commitment.X,
            y: blob.commitment.Y,
        },
        length: blob.length,
    })
}

/// Builders for certified calldata over real certificates, for tests in this and dependent crates.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{FixedBytes, U256};
    use canoe_bindings as sol_struct;

    fn g2() -> sol_struct::G2Point {
        sol_struct::G2Point {
            X: [U256::from(1), U256::from(2)],
            Y: [U256::from(3), U256::from(4)],
        }
    }

    fn cursor(seed: u64) -> CertifiedCursor {
        CertifiedCursor {
            height: seed,
            index: seed as u32,
            blockNumber: seed + 1,
            epochNum: seed + 2,
            framesDigest: FixedBytes::repeat_byte(seed as u8),
            quorumSnapshotHash: FixedBytes::repeat_byte(0x77),
        }
    }

    /// An ABI-encoded EigenDACertV3 whose blob commitment is `point` over `length` field elements.
    pub fn eigenda_cert(point: G1Point, length: u32) -> Vec<u8> {
        let g1 = sol_struct::G1Point {
            X: U256::from(5),
            Y: U256::from(6),
        };
        sol_struct::EigenDACertV3 {
            batchHeaderV2: sol_struct::BatchHeaderV2 {
                batchRoot: FixedBytes::repeat_byte(0x11),
                referenceBlockNumber: 42,
            },
            blobInclusionInfo: sol_struct::BlobInclusionInfo {
                blobCertificate: sol_struct::BlobCertificate {
                    blobHeader: sol_struct::BlobHeaderV2 {
                        version: 0,
                        quorumNumbers: Bytes::from(vec![0, 1]),
                        commitment: blob_commitment(point, length),
                        paymentHeaderHash: FixedBytes::repeat_byte(0x22),
                    },
                    signature: Bytes::from(vec![0x33; 65]),
                    relayKeys: vec![7],
                },
                blobIndex: 3,
                inclusionProof: Bytes::from(vec![0x44; 32]),
            },
            nonSignerStakesAndSignature: sol_struct::NonSignerStakesAndSignature {
                nonSignerQuorumBitmapIndices: vec![],
                nonSignerPubkeys: vec![],
                quorumApks: vec![g1.clone()],
                apkG2: g2(),
                sigma: g1,
                quorumApkIndices: vec![1],
                totalStakeIndices: vec![2],
                nonSignerStakeIndices: vec![vec![]],
            },
            signedQuorumNumbers: Bytes::from(vec![0, 1]),
        }
        .abi_encode()
    }

    /// The certificate's blob commitment as the ABI struct.
    pub fn blob_commitment(point: G1Point, length: u32) -> sol_struct::BlobCommitment {
        sol_struct::BlobCommitment {
            commitment: point.to_sol(),
            lengthCommitment: g2(),
            lengthProof: g2(),
            length,
        }
    }

    /// The ABI body of a batch commitment over `cert` attesting `eigenda_commitment`.
    pub fn batch_commitment_body(cert: Vec<u8>, eigenda_commitment: Vec<u8>) -> Vec<u8> {
        BatchCommitment {
            eigendaCert: cert.into(),
            eigendaCommitment: eigenda_commitment.into(),
            prevCursor: cursor(8),
            cursor: cursor(9),
            certifierSig: Bytes::from(vec![0x5c; CERTIFIER_SIG_BYTES]),
        }
        .abi_encode()
    }

    /// Calldata `0x01 0x80 || body` of a well-formed certified commitment whose certificate names
    /// `point` over `length` field elements and whose attestation is that certificate's digest.
    pub fn certified_calldata(point: G1Point, length: u32) -> Bytes {
        let digest = keccak256(blob_commitment(point, length).abi_encode());
        let body = batch_commitment_body(eigenda_cert(point, length), digest.to_vec());
        let mut calldata = vec![ALTDA_DERIVATION_VERSION, CERTIFIED_COMMITMENT_TYPE];
        calldata.extend_from_slice(&body);
        calldata.into()
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use alloy_primitives::{hex, U256};
    use serde::Deserialize;

    const VECTOR: &str = include_str!("../testdata/certified_calldata.json");

    #[derive(Deserialize)]
    struct Vector {
        schema: String,
        generated_by: String,
        case_count: usize,
        derivation_version: String,
        certified_commitment_type: String,
        altda_prefix_len: usize,
        certifier_sig_bytes: usize,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        calldata_hex: String,
        #[serde(default)]
        body_hex: String,
        prefix_accepted: bool,
        canonical: bool,
        #[serde(default)]
        eigenda_cert_hex: String,
        #[serde(default)]
        eigenda_commitment_hex: String,
        #[serde(default)]
        certifier_sig_hex: String,
    }

    fn load_vector() -> Vector {
        let v: Vector = serde_json::from_str(VECTOR).unwrap();
        // A vector that parsed to nothing would let every assertion pass without exercising one
        // input.
        assert!(!v.cases.is_empty());
        assert_eq!(v.case_count, v.cases.len());
        assert_eq!(v.schema, "mega-block-certifier/certified_calldata");
        assert_eq!(
            v.generated_by,
            "contracts/script/GenCertifiedCalldata.s.sol"
        );
        v
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// The prefix constants are the ones the vector states, so a change to either has to be a
    /// change to the vector the settling contract reads.
    #[test]
    fn prefix_matches_vector() {
        let v = load_vector();
        assert_eq!(unhex(&v.derivation_version), [ALTDA_DERIVATION_VERSION]);
        assert_eq!(
            unhex(&v.certified_commitment_type),
            [CERTIFIED_COMMITMENT_TYPE]
        );
        assert_eq!(v.altda_prefix_len, 2);
        assert_eq!(v.certifier_sig_bytes, CERTIFIER_SIG_BYTES);
    }

    /// Every case, read by the strict decoder: it must accept exactly the cases whose prefix is the
    /// certified pair, whose body is canonical, and whose signature is 65 bytes.
    #[test]
    fn strict_decode_matches_vector() {
        let v = load_vector();
        let (mut accepted, mut refused) = (0, 0);
        for case in &v.cases {
            let calldata = unhex(&case.calldata_hex);
            let sig_ok = !case.certifier_sig_hex.is_empty()
                && unhex(&case.certifier_sig_hex).len() == CERTIFIER_SIG_BYTES;
            let want_accept = case.prefix_accepted && case.canonical && sig_ok;

            let got = calldata
                .strip_prefix(&[ALTDA_DERIVATION_VERSION, CERTIFIED_COMMITMENT_TYPE])
                .ok_or(CertifiedCommitmentError::NotCertifiedPrefix)
                .and_then(decode_body);
            if !want_accept {
                assert!(got.is_err(), "{} must be refused", case.name);
                refused += 1;
                continue;
            }
            let got = got.unwrap_or_else(|e| panic!("{} must decode: {e}", case.name));
            assert_eq!(
                calldata[2..],
                unhex(&case.body_hex)[..],
                "{}: body",
                case.name
            );
            assert_eq!(
                got.eigendaCert[..],
                unhex(&case.eigenda_cert_hex)[..],
                "{}",
                case.name
            );
            assert_eq!(
                got.eigendaCommitment[..],
                unhex(&case.eigenda_commitment_hex)[..],
                "{}",
                case.name
            );
            accepted += 1;
        }
        // Without both halves a decoder that always says yes, or always no, would pass.
        assert!(accepted > 0 && refused > 0);
    }

    /// The vector's certificates are arbitrary bytes, so none of them survives attestation: a
    /// decodable commitment is still not a certified commitment until its certificate is.
    #[test]
    fn vector_certificates_are_not_attested() {
        let v = load_vector();
        for case in v.cases.iter().filter(|c| c.prefix_accepted && c.canonical) {
            assert!(CertifiedCommitment::from_calldata(&unhex(&case.calldata_hex)).is_err());
        }
    }

    const ATTESTED: &str = include_str!("../testdata/attested_certified.json");

    #[derive(Deserialize)]
    struct AttestedVector {
        generated_by: String,
        cases: Vec<AttestedCase>,
    }

    #[derive(Deserialize)]
    struct AttestedCase {
        name: String,
        calldata: String,
        eigenda_cert: String,
        blob_commitment_hash: String,
        commitment_x: String,
        commitment_y: String,
        length: u32,
    }

    /// Every other positive case here is built by [certified_calldata], which hashes the blob
    /// commitment with this crate's own encoder: had `canoe_bindings`' BlobCommitment a layout
    /// other than the eleven words mega-block-certifier's `_blobCommitmentHash` hashes, they would
    /// all pass while every real batch was skipped. These certificates and hashes are Solidity's.
    #[test]
    fn solidity_attested_certificates_are_accepted() {
        let v: AttestedVector = serde_json::from_str(ATTESTED).unwrap();
        assert!(v.generated_by.contains("GenAttestedCertified.s.sol"));
        assert_eq!(v.cases.len(), 2);
        for case in &v.cases {
            let cert =
                canoe_bindings::EigenDACertV3::abi_decode_validate(&unhex(&case.eigenda_cert))
                    .unwrap();
            let blob = cert.blobInclusionInfo.blobCertificate.blobHeader.commitment;
            assert_eq!(
                keccak256(blob.abi_encode())[..],
                unhex(&case.blob_commitment_hash)[..],
                "{}: Rust's commitment hash is not Solidity's",
                case.name
            );

            let commitment = CertifiedCommitment::from_calldata(&unhex(&case.calldata))
                .unwrap_or_else(|e| panic!("{} must be certified: {e}", case.name));
            assert_eq!(
                *commitment.blob(),
                AttestedBlob {
                    commitment: G1Point {
                        x: U256::from_be_slice(&unhex(&case.commitment_x)),
                        y: U256::from_be_slice(&unhex(&case.commitment_y)),
                    },
                    length: case.length,
                },
                "{}",
                case.name
            );
        }
    }

    fn point() -> G1Point {
        G1Point {
            x: U256::from(0x1234),
            y: U256::from(0x5678),
        }
    }

    #[test]
    fn attested_commitment_round_trips() {
        let calldata = certified_calldata(point(), 4);
        let commitment = CertifiedCommitment::from_calldata(&calldata).unwrap();
        assert_eq!(commitment.body()[..], calldata[2..]);
        assert_eq!(
            *commitment.blob(),
            AttestedBlob {
                commitment: point(),
                length: 4
            }
        );

        let mut key = vec![CERTIFIED_COMMITMENT_TYPE];
        key.extend_from_slice(&calldata[2..]);
        assert_eq!(commitment.retrieval_key(), key);

        let hint = commitment.payload_hint(0x0102_0304_0506_0708);
        assert_eq!(hint[..key.len()], key[..]);
        assert_eq!(hint[key.len()..], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            CertifiedCommitment::from_payload_hint(&hint).unwrap(),
            (commitment, 0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn attestation_must_be_the_blob_commitment_digest() {
        let cert = eigenda_cert(point(), 4);
        // The digest of a blob commitment that differs only in its length.
        let wrong = keccak256(blob_commitment(point(), 8).abi_encode());
        let mut calldata = vec![ALTDA_DERIVATION_VERSION, CERTIFIED_COMMITMENT_TYPE];
        calldata.extend_from_slice(&batch_commitment_body(cert, wrong.to_vec()));
        assert_eq!(
            CertifiedCommitment::from_calldata(&calldata),
            Err(CertifiedCommitmentError::CommitmentMismatch)
        );
    }

    #[test]
    fn certificate_must_decode() {
        let digest = keccak256(blob_commitment(point(), 4).abi_encode());
        let body = batch_commitment_body(vec![0xbe, 0xef], digest.to_vec());
        assert_eq!(
            CertifiedCommitment::from_body(&body),
            Err(CertifiedCommitmentError::CertDecode)
        );
    }

    /// op-node's go-ethereum `Unpack` refuses a `uint32` word above `2^32 - 1`, so a certificate
    /// whose blob length carries dirty high bits is skipped there even when the attestation is the
    /// digest of the clean re-encoding. Reading the low four bytes here would accept it and fork.
    #[test]
    fn dirty_narrow_int_in_certificate_is_refused() {
        let length = 0x7a3c_51e9;
        let mut cert = eigenda_cert(point(), length);
        let mut clean_word = [0u8; 32];
        clean_word[28..].copy_from_slice(&length.to_be_bytes());
        let at: Vec<usize> = (0..cert.len())
            .step_by(32)
            .filter(|&i| cert[i..i + 32] == clean_word)
            .collect();
        assert_eq!(
            at.len(),
            1,
            "the length word must be unique in the certificate"
        );
        cert[at[0] + 27] = 0x01;

        let clean_digest = keccak256(blob_commitment(point(), length).abi_encode());
        let body = batch_commitment_body(cert, clean_digest.to_vec());
        assert_eq!(
            CertifiedCommitment::from_body(&body),
            Err(CertifiedCommitmentError::CertDecode)
        );
    }

    #[test]
    fn malformed_hints_are_refused() {
        let hint = CertifiedCommitment::from_calldata(&certified_calldata(point(), 4))
            .unwrap()
            .payload_hint(7);
        assert_eq!(
            CertifiedCommitment::from_payload_hint(&hint[..7]),
            Err(CertifiedCommitmentError::MalformedHint)
        );
        let mut legacy_type = hint.clone();
        legacy_type[0] = 0x01;
        assert_eq!(
            CertifiedCommitment::from_payload_hint(&legacy_type),
            Err(CertifiedCommitmentError::MalformedHint)
        );
        // Dropping the block number leaves a body with eight bytes missing.
        assert!(CertifiedCommitment::from_payload_hint(&hint[..hint.len() - 8]).is_err());
    }

    #[test]
    fn key_spaces_are_disjoint() {
        let commitment =
            CertifiedCommitment::from_calldata(&certified_calldata(point(), 4)).unwrap();
        let other = CertifiedCommitment::from_calldata(&certified_calldata(point(), 8)).unwrap();
        assert_ne!(commitment.field_element_key(0), commitment.kzg_proof_key());
        assert_ne!(
            commitment.field_element_key(0),
            commitment.field_element_key(1)
        );
        assert_ne!(commitment.field_element_key(0), other.field_element_key(0));
        assert_eq!(commitment.field_element_key(1)[72..], 1u64.to_be_bytes());
    }
}
