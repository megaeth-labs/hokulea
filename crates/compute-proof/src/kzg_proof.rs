//! This is a crate for generating a kzg proof for an eigenda blob. In the future,
//! such proof is carried inside the blob header. Then it can be removed. This crate access filesystem,
//! cannot be used in any fault proof or zk vm.
use crate::G1_SRS;
use alloy_primitives::{Bytes, FixedBytes};
use ark_bn254::G1Affine;
use num::BigUint;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_primitives::errors::KzgError;
use rust_kzg_bn254_prover::kzg::KZG;
use rust_kzg_bn254_prover::srs::SRS;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

/// This function computes a KZG proof for a eigenDA blob
/// nitro code <https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141>
/// could refactor in the future, such that both host and client can compute the proof
pub fn compute_kzg_proof(encoded_payload: &[u8]) -> Result<Bytes, KzgError> {
    compute_kzg_proof_with_srs(encoded_payload, &G1_SRS)
}

/// This function computes a KZG proof for a eigenDA blob
/// nitro code <https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L141>
/// could refactor in the future, such that both host and client can compute the proof
pub fn compute_kzg_proof_with_srs<'s>(
    encoded_payload: &[u8],
    srs: &SRS<'s>,
) -> Result<Bytes, KzgError> {
    let (_, proof) = compute_kzg_commitment_and_proof_with_srs(encoded_payload, srs)?;
    Ok(proof.into())
}

/// Computes the KZG commitment of an encoded payload in evaluation form, the point an EigenDA
/// certificate carries for it, and the blob proof binding the payload to that point. Both are
/// returned as `x || y`, 32 bytes big-endian each.
pub fn compute_kzg_commitment_and_proof(
    encoded_payload: &[u8],
) -> Result<(FixedBytes<64>, FixedBytes<64>), KzgError> {
    compute_kzg_commitment_and_proof_with_srs(encoded_payload, &G1_SRS)
}

/// [compute_kzg_commitment_and_proof] against a given SRS.
pub fn compute_kzg_commitment_and_proof_with_srs<'s>(
    encoded_payload: &[u8],
    srs: &SRS<'s>,
) -> Result<(FixedBytes<64>, FixedBytes<64>), KzgError> {
    let mut kzg = KZG::new();
    kzg.calculate_and_store_roots_of_unity(encoded_payload.len() as u64)?;

    // The encoded payload is a polynomial presented in its evaluation form
    let blob = Blob::new(encoded_payload)?;
    let input_poly = blob.to_polynomial_eval_form()?;

    let commitment = kzg.commit_eval_form(&input_poly, srs)?;
    let proof = kzg.compute_blob_proof(&blob, &commitment, srs)?;
    Ok((g1_to_be_bytes(&commitment), g1_to_be_bytes(&proof)))
}

/// A G1 point as `x || y`, 32 bytes big-endian each.
fn g1_to_be_bytes(point: &G1Affine) -> FixedBytes<64> {
    let x: BigUint = point.x.into();
    let y: BigUint = point.y.into();
    let mut bytes = FixedBytes::<64>::ZERO;
    bytes[..32].copy_from_slice(&convert_biguint_to_be_32_bytes(&x));
    bytes[32..].copy_from_slice(&convert_biguint_to_be_32_bytes(&y));
    bytes
}

/// This function convert a BigUint into 32Bytes vector in big endian format
//pub fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
pub fn convert_biguint_to_be_32_bytes(biguint: &BigUint) -> [u8; 32] {
    let mut output = [0; 32];
    let be_bytes = biguint.to_bytes_be();
    let padding = 32 - be_bytes.len();
    output[padding..].copy_from_slice(&be_bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, U256};
    use eigenda_cert::G1Point;
    use hokulea_eigenda::EncodedPayload;
    use hokulea_proof::preloaded_eigenda_provider::batch_verify;
    use rust_kzg_bn254_primitives::helpers::{pad_payload, read_g1_point_from_bytes_be};
    use serde::Deserialize;
    use std::borrow::Cow;

    /// The first 64 compressed points of EigenDA's g1.point, byte for byte.
    const SRS_PREFIX: &[u8] = include_bytes!("../testdata/g1.point.first64");
    /// Commitments EigenDA's own Go committer computed, shared with op-node and the certifier.
    const KZG_VECTOR: &str = include_str!("../testdata/eigenda_kzg_commitment.json");

    #[derive(Deserialize)]
    struct KzgVector {
        schema: String,
        cases: Vec<KzgCase>,
    }

    #[derive(Deserialize)]
    struct KzgCase {
        name: String,
        payload_hex: String,
        padded_hex: String,
        commitment_uncompressed_64: String,
    }

    fn srs_prefix() -> SRS<'static> {
        let points: Vec<G1Affine> = SRS_PREFIX
            .chunks_exact(32)
            .map(|point| read_g1_point_from_bytes_be(point).unwrap())
            .collect();
        assert_eq!(points.len(), 64);
        SRS {
            g1: Cow::Owned(points),
            order: 64,
        }
    }

    fn g1_point(bytes: &FixedBytes<64>) -> G1Point {
        G1Point {
            x: U256::from_be_slice(&bytes[..32]),
            y: U256::from_be_slice(&bytes[32..]),
        }
    }

    /// The bare arithmetic and the SRS prefix against EigenDA's committer, which commits to the
    /// padded payload's symbols read as polynomial coefficients.
    #[test]
    fn coefficient_form_matches_eigenda_vector() {
        let vector: KzgVector = serde_json::from_str(KZG_VECTOR).unwrap();
        assert_eq!(vector.schema, "mega-block-certifier/eigenda_kzg_commitment");
        assert!(!vector.cases.is_empty());
        let srs = srs_prefix();
        for case in &vector.cases {
            let payload = hex::decode(&case.payload_hex).unwrap();
            let padded = hex::decode(&case.padded_hex).unwrap();
            assert_eq!(pad_payload(&payload), padded, "{}", case.name);

            // the encoded payload's body is the same padding the vector states
            let encoded = EncodedPayload::encode(&payload).unwrap();
            assert_eq!(
                encoded.serialize()[32..32 + padded.len()],
                padded[..],
                "{}",
                case.name
            );

            let poly = Blob::new(&padded)
                .unwrap()
                .to_polynomial_coeff_form()
                .unwrap();
            let commitment = KZG::new().commit_coeff_form(&poly, &srs).unwrap();
            assert_eq!(
                hex::encode(g1_to_be_bytes(&commitment)),
                case.commitment_uncompressed_64,
                "{}",
                case.name
            );
        }
    }

    /// The commitment a certificate carries is over the encoded payload, header included, read as
    /// EVALUATIONS (op-node eigenda/payload.go). Pinned against two real dispersals whose payloads
    /// occupy the same four symbols and differ in the length the header names.
    #[test]
    fn evaluation_form_matches_real_dispersals() {
        let dispersals = [
            (
                "block-certifier eigenda smoke 1790059466",
                "1cfc201448ba83ceabd0dc0028825f9ba1e056e786120c3c165afe2672b9e1ed",
                "0df0b0aac065c8bc3679aef9d5cf5c2ec5cec49684c9d819f6084807af9814d4",
            ),
            (
                "block-certifier eigenda cert fixture v1",
                "26a58b041df9851c07e57a475d4f16b45dd8a31c7c75d4f00998bd264d23d244",
                "1d00c54fae15a334568a92b4caef7058e7e981961598b38cd9b8be551e27076f",
            ),
        ];
        let srs = srs_prefix();
        for (payload, x, y) in dispersals {
            let encoded = EncodedPayload::encode(payload.as_bytes()).unwrap();
            assert_eq!(encoded.num_field_element(), 4);

            let (commitment, proof) =
                compute_kzg_commitment_and_proof_with_srs(encoded.serialize(), &srs).unwrap();
            assert_eq!(hex::encode(&commitment[..32]), x, "{payload}");
            assert_eq!(hex::encode(&commitment[32..]), y, "{payload}");

            // the full embedded SRS starts with the same points
            let (full_commitment, _) =
                compute_kzg_commitment_and_proof(encoded.serialize()).unwrap();
            assert_eq!(full_commitment, commitment, "{payload}");

            // the proof binds the encoded payload to the certificate's point
            let blob = Blob::new(encoded.serialize()).unwrap();
            assert!(batch_verify(&[blob], &[g1_point(&commitment)], &[proof]));

            // committing to the same symbols as coefficients is a different, well-formed point
            let poly = Blob::new(encoded.serialize())
                .unwrap()
                .to_polynomial_coeff_form()
                .unwrap();
            let coefficients = KZG::new().commit_coeff_form(&poly, &srs).unwrap();
            assert_ne!(g1_to_be_bytes(&coefficients), commitment);
        }
    }

    #[test]
    fn test_convert_biguint_to_be_32_bytes() {
        // most significant bit 1
        let a = vec![129, 255];
        let a_biguint = BigUint::from_bytes_be(&a);
        let out_a = convert_biguint_to_be_32_bytes(&a_biguint);

        let mut expected = vec![0u8; 30];
        expected.extend_from_slice(&a);
        assert_eq!(&out_a[..], &expected[..]);

        // most significant bit 0 of 2 bytes are 0
        let a = vec![1; 32];
        let a_biguint = BigUint::from_bytes_be(&a);
        let out_a = convert_biguint_to_be_32_bytes(&a_biguint);

        let expected = a;
        assert_eq!(&out_a[..], &expected[..]);
    }
}
