use std::str::FromStr;

use alloy::primitives::{Address, PrimitiveSignature as Signature};
use axum::http::HeaderMap;

use crate::primitives::signature::SignatureError;

use super::spec::{CommitmentError, SIGNATURE_HEADER};

/// Extracts the signature ([SIGNATURE_HEADER]) from the HTTP headers.
#[inline]
pub fn auth_from_headers(headers: &HeaderMap) -> Result<(Address, Signature), CommitmentError> {
    let auth = headers.get(SIGNATURE_HEADER).ok_or(CommitmentError::NoSignature)?;

    // Remove the "0x" prefix
    let auth = auth.to_str().map_err(|_| CommitmentError::MalformedHeader)?;

    let mut split = auth.split(':');

    let address = split.next().ok_or(CommitmentError::MalformedHeader)?;
    let address = Address::from_str(address).map_err(|_| CommitmentError::MalformedHeader)?;

    let sig = split.next().ok_or(CommitmentError::MalformedHeader)?;
    let sig =
        Signature::from_str(sig).map_err(|_| CommitmentError::InvalidSignature(SignatureError))?;

    Ok((address, sig))
}

#[cfg(test)]
mod test {
    use alloy::{
        hex::ToHexExt,
        primitives::TxHash,
        signers::{local::PrivateKeySigner, Signer},
    };

    use super::*;

    #[tokio::test]
    async fn test_signature_from_headers() {
        let mut headers = HeaderMap::new();
        let hash = TxHash::random();
        let signer = PrivateKeySigner::random();
        let addr = signer.address();

        let expected_sig = signer.sign_hash(&hash).await.unwrap();
        headers.insert(
            SIGNATURE_HEADER,
            format!("{addr}:{}", expected_sig.as_bytes().encode_hex()).parse().unwrap(),
        );

        let (address, signature) = auth_from_headers(&headers).unwrap();
        assert_eq!(signature, Signature::try_from(expected_sig.as_bytes().as_ref()).unwrap());
        assert_eq!(address, addr);
    }
}
