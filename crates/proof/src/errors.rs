use alloc::string::ToString;
use hokulea_eigenda::HokuleaErrorKind;
use kona_preimage::errors::PreimageOracleError;

/// Custom hokulea preimage error
#[derive(Debug, thiserror::Error)]
pub enum HokuleaOracleProviderError {
    /// Preimage Oracle error from kona
    /// <https://github.com/op-rs/kona/blob/174b2ac5ad3756d4469553c7777b04056f9d151c/crates/proof/proof/src/errors.rs#L18>
    #[error("Preimage oracle error: {0}")]
    Preimage(#[from] PreimageOracleError),
    /// The host served a certified encoded payload whose KZG proof does not bind it to the
    /// certificate's blob commitment. The host must never serve one, so nothing can be retried.
    #[error("certified encoded payload is not bound to the certificate's blob commitment")]
    UnboundCertifiedPayload,
}

impl From<HokuleaOracleProviderError> for HokuleaErrorKind {
    fn from(val: HokuleaOracleProviderError) -> Self {
        let err = match val {
            HokuleaOracleProviderError::Preimage(err) => err,
            HokuleaOracleProviderError::UnboundCertifiedPayload => {
                return HokuleaErrorKind::Critical(val.to_string())
            }
        };
        match err {
            // since the bidirectional channel already closed, the system must restart to recover
            // therefore return critical. We make a special case for PreimageOracleError
            PreimageOracleError::IOError(e) => HokuleaErrorKind::Critical(alloc::format!(
                "HokuleaOracleProviderError::PreimageOracleError::IOError {e}"
            )),
            // in kona, all Preimage error are grouped into backend error <https://github.com/op-rs/kona/blob/4ef01882824b84d078ead9f834f4f78213dd6ef3/crates/protocol/derive/src/sources/blobs.rs#L136>
            // which is considered a temp issue
            _ => HokuleaErrorKind::Temporary(alloc::format!(
                "HokuleaOracleProviderError::Preimage: {err}"
            )),
        }
    }
}
