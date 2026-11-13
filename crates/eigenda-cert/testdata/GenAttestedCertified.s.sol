// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Generator of attested_certified.json. Not built in this repository: copy it into
// mega-block-certifier's contracts/script/ and run there (attested_certified.json records the
// command and the mega-block-certifier commit). It prints one JSON object per case on stdout; the file's `cases` are those
// objects in order.
//
// Every value a hokulea test compares against comes from mega-block-certifier's Solidity: the
// certificates are `abi.encode`d here or taken from transactions the Sepolia shadow inbox
// accepted, and `blob_commitment_hash` is the production `_blobCommitmentHash`, after the
// production `_decodeCanonical` has accepted the certificate.

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {BatchInbox, Cursor, BatchCommitment} from "../src/BatchInbox.sol";
import {EigenDACertV3Types as T} from "../src/EigenDACertV3Types.sol";
import {EigenDAHybridVerifier, Freshness} from "../src/EigenDAHybridVerifier.sol";
import {IEigenDACertVerifierRouter} from "../src/EigenDAHybridInterfaces.sol";

/// Exposes the verifier's commitment hash. Nothing pinned, so construction reads no registry.
contract BlobCommitmentHashHarness is EigenDAHybridVerifier {
    constructor()
        EigenDAHybridVerifier(IEigenDACertVerifierRouter(address(1)), address(0), Freshness.FollowUpstreamLive)
    {}

    function blobCommitmentHash(bytes calldata cert) external pure returns (bytes32) {
        _decodeCanonical(cert);
        return _blobCommitmentHash(cert);
    }
}

contract GenAttestedCertified is Script {
    using stdJson for string;

    BlobCommitmentHashHarness private harness;
    BatchInbox private constants_;

    function run() external {
        harness = new BlobCommitmentHashHarness();
        constants_ = new BatchInbox();

        console.log(_synthetic());
        console.log(_sepolia());
    }

    /// A certificate whose blob commitment fields are all distinct, so a reader that swapped
    /// lengthCommitment and lengthProof, or a coordinate pair, hashes differently.
    function _synthetic() internal returns (string memory) {
        T.EigenDACertV3 memory c;
        c.batchHeader = T.BatchHeaderV2(bytes32(uint256(0x11)), 42);

        T.BlobHeaderV2 memory header;
        header.version = 0;
        header.quorumNumbers = hex"0001";
        header.commitment = T.BlobCommitment(
            T.G1Point(0x1234, 0x5678),
            T.G2Point([uint256(0xa1), uint256(0xa2)], [uint256(0xa3), uint256(0xa4)]),
            T.G2Point([uint256(0xb1), uint256(0xb2)], [uint256(0xb3), uint256(0xb4)]),
            0x01234567
        );
        header.paymentHeaderHash = bytes32(uint256(0x22));
        c.blobInclusionInfo.blobCertificate.blobHeader = header;
        c.blobInclusionInfo.blobCertificate.signature = new bytes(65);
        c.blobInclusionInfo.blobCertificate.relayKeys = new uint32[](1);
        c.blobInclusionInfo.blobCertificate.relayKeys[0] = 7;
        c.blobInclusionInfo.blobIndex = 3;
        c.blobInclusionInfo.inclusionProof = abi.encodePacked(bytes32(uint256(0x44)));

        c.nonSignerStakesAndSignature.quorumApks = new T.G1Point[](1);
        c.nonSignerStakesAndSignature.quorumApks[0] = T.G1Point(5, 6);
        c.nonSignerStakesAndSignature.apkG2 = T.G2Point([uint256(1), uint256(2)], [uint256(3), uint256(4)]);
        c.nonSignerStakesAndSignature.sigma = T.G1Point(5, 6);
        c.nonSignerStakesAndSignature.quorumApkIndices = new uint32[](1);
        c.nonSignerStakesAndSignature.totalStakeIndices = new uint32[](1);
        c.nonSignerStakesAndSignature.nonSignerStakeIndices = new uint32[][](1);
        c.signedQuorumNumbers = hex"0001";

        bytes memory cert = abi.encode(c);
        Cursor memory prev = Cursor(8, 8, 9, 10, bytes32(uint256(8)), bytes32(uint256(0x77)));
        Cursor memory next = Cursor(9, 9, 10, 11, bytes32(uint256(9)), bytes32(uint256(0x77)));
        bytes memory body = abi.encode(
            BatchCommitment(cert, abi.encodePacked(harness.blobCommitmentHash(cert)), prev, next, new bytes(65))
        );
        return _case("synthetic", "abi.encode of a synthetic EigenDACertV3", body);
    }

    /// The certificate of the first transaction of vectors/sepolia_certified_txs.json: a real
    /// EigenDA certificate with non-signers that the shadow inbox accepted. That transaction is in
    /// the retired shadow layout (0x01 0x02 prefix, the certificate at the offset in tuple word 0)
    /// and attests a commitment from before `commitment_of` became the BlobCommitment digest, so
    /// only the certificate is taken; it is rewrapped in the current BatchCommitment with the
    /// verifier's hash as its attestation.
    function _sepolia() internal returns (string memory) {
        string memory txs = vm.readFile("../vectors/sepolia_certified_txs.json");
        bytes memory raw = txs.readBytes(".transactions[0].calldata_hex");
        // Skip the two prefix bytes and the outer tuple offset.
        uint256 tuple = 2 + 32;
        uint256 certAt = tuple + uint256(_word(raw, tuple));
        bytes memory cert = _slice(raw, certAt + 32, uint256(_word(raw, certAt)));
        require(cert.length == txs.readUint(".transactions[0].cert_bytes"), "certificate length");

        Cursor memory prev = Cursor(8, 8, 9, 10, bytes32(uint256(8)), bytes32(uint256(0x77)));
        Cursor memory next = Cursor(9, 9, 10, 11, bytes32(uint256(9)), bytes32(uint256(0x77)));
        bytes memory body = abi.encode(
            BatchCommitment(cert, abi.encodePacked(harness.blobCommitmentHash(cert)), prev, next, new bytes(65))
        );
        return _case("sepolia", txs.readString(".transactions[0].hash"), body);
    }

    function _word(bytes memory b, uint256 at) internal pure returns (bytes32) {
        return bytes32(_slice(b, at, 32));
    }

    function _slice(bytes memory b, uint256 at, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[at + i];
        }
    }

    function _case(string memory key, string memory source, bytes memory body) internal returns (string memory) {
        BatchCommitment memory bc = abi.decode(body, (BatchCommitment));
        T.EigenDACertV3 memory c = abi.decode(bc.eigendaCert, (T.EigenDACertV3));
        T.BlobCommitment memory blob = c.blobInclusionInfo.blobCertificate.blobHeader.commitment;

        vm.serializeString(key, "name", key);
        vm.serializeString(key, "source", source);
        vm.serializeBytes(
            key,
            "calldata",
            abi.encodePacked(constants_.DERIVATION_VERSION(), constants_.CERTIFIED_COMMITMENT_TYPE(), body)
        );
        vm.serializeBytes(key, "eigenda_cert", bc.eigendaCert);
        vm.serializeBytes32(key, "blob_commitment_hash", harness.blobCommitmentHash(bc.eigendaCert));
        vm.serializeBytes32(key, "commitment_x", bytes32(blob.commitment.X));
        vm.serializeBytes32(key, "commitment_y", bytes32(blob.commitment.Y));
        return vm.serializeUint(key, "length", blob.length);
    }
}
