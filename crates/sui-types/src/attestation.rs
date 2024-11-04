// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use crate::error::{SuiError, SuiResult};
use std::collections::BTreeMap;

use boring_signal::bn::BigNum;
use boring_signal::ecdsa::EcdsaSig;
use boring_signal::stack;
use boring_signal::x509::store::X509StoreBuilder;
use boring_signal::x509::{X509StoreContext, X509};
use ciborium::value::{Integer, Value};
use prost::DecodeError;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;
#[cfg(test)]
#[path = "unit_tests/attestation_tests.rs"]
mod attestation_tests;

const ROOT_CERTIFICATE_PEM: &[u8] = include_bytes!("./nitro_root_certificate.pem");

#[derive(Debug, PartialEq, Eq)]
pub enum NitroError {
    /// Invalid CBOR
    InvalidCbor,
    /// Invalid COSE_Sign1
    InvalidCoseSign1,
    /// Invalid signature
    InvalidSignature,
    /// Invalid attestation document
    InvalidAttestationDoc,
    /// Invalid certificate: {0}
    InvalidCertificate(String),
    /// Invalid PCRs
    InvalidPcrs,
    /// Invalid Public Key
    InvalidPublicKey,
    /// User data field is absent from the attestation document
    UserDataMissing,
    /// Invalid User Data
    InvalidUserData,
}

impl From<ciborium::de::Error<std::io::Error>> for NitroError {
    fn from(_err: ciborium::de::Error<std::io::Error>) -> NitroError {
        NitroError::InvalidCbor
    }
}

impl From<boring_signal::error::ErrorStack> for NitroError {
    fn from(err: boring_signal::error::ErrorStack) -> NitroError {
        NitroError::InvalidCertificate(err.to_string())
    }
}

impl From<DecodeError> for NitroError {
    fn from(_err: DecodeError) -> Self {
        NitroError::InvalidUserData
    }
}

/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
pub fn attestation_verify_inner(
    document_data: &[u8],
    pk: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
) -> SuiResult<()> {
    // Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    // Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
    let cose_sign1 = CoseSign1::from_bytes(document_data)
        .map_err(|_| SuiError::AttestationFailedToVerify("cannot parse cose sign1".to_string()))?;
    let now = SystemTime::now();
    // Step 2. Exract the attestation document from the COSE_Sign1 structure and Verify the certificate's chain
    let document = cose_sign1
        .extract_attestation_doc(now)
        .map_err(|_| SuiError::AttestationFailedToVerify("invalid signature".to_string()))?;

    cose_sign1
        .validate_header()
        .map_err(|_| SuiError::AttestationFailedToVerify("InvalidCoseSign1".to_string()))?;
    document
        .validate_pcrs(&[pcr0, pcr1, pcr2])
        .map_err(|_| SuiError::AttestationFailedToVerify("InvalidPcrs".to_string()))?;
    let user_data = document
        .user_data
        .ok_or(SuiError::AttestationFailedToVerify(
            "user data missing".to_string(),
        ))?;
    if user_data.ct_eq(pk).into() {
        Ok(())
    } else {
        Err(SuiError::AttestationFailedToVerify(
            "user data mismatch".to_string(),
        ))
    }
}

struct CoseSign1 {
    protected_header: Vec<u8>,
    // nitro has no unprotected header
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let cbor: serde_cbor::Value = serde_cbor::from_slice(bytes)
            .map_err(|err| format!("AttestationDocument::parse from_slice failed:{:?}", err))?;
        let elements = match cbor {
            serde_cbor::Value::Array(elements) => elements,
            _ => panic!("AttestationDocument::parse Unknown field cbor:{:?}", cbor),
        };
        let protected = match &elements[0] {
            serde_cbor::Value::Bytes(prot) => prot,
            _ => panic!(
                "AttestationDocument::parse Unknown field protected:{:?}",
                elements[0]
            ),
        };
        let _unprotected = match &elements[1] {
            serde_cbor::Value::Map(unprot) => unprot,
            _ => panic!(
                "AttestationDocument::parse Unknown field unprotected:{:?}",
                elements[1]
            ),
        };
        let payload = match &elements[2] {
            serde_cbor::Value::Bytes(payld) => payld,
            _ => panic!(
                "AttestationDocument::parse Unknown field payload:{:?}",
                elements[2]
            ),
        };
        let signature = match &elements[3] {
            serde_cbor::Value::Bytes(sig) => sig,
            _ => panic!(
                "AttestationDocument::parse Unknown field signature:{:?}",
                elements[3]
            ),
        };
        Ok(CoseSign1 {
            protected_header: protected.to_vec(),
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        })
    }

    pub fn extract_attestation_doc(
        &self,
        now: SystemTime,
    ) -> Result<AttestationDocument, NitroError> {
        let hash = Sha384::digest(self.to_canonical());
        let r = BigNum::from_slice(&self.signature[..48]).expect("can extract r");
        let s = BigNum::from_slice(&self.signature[48..]).expect("can extract s");
        let sig = EcdsaSig::from_private_components(r, s).expect("can initialize signature");

        let doc = AttestationDocument::parse_payload(&self.payload).expect("can parse doc");
        let cert = doc.verified_cert(now)?;
        let key = cert
            .public_key()
            .and_then(|pub_key| pub_key.ec_key())
            .expect("has EC key");
        let is_valid = sig.verify(hash.as_slice(), &key).expect("can verify");
        if !is_valid {
            return Err(NitroError::InvalidSignature);
        }
        Ok(doc)
    }

    pub fn validate_header(&self) -> Result<(), NitroError> {
        let is_valid = {
            let mut is_valid = true;
            is_valid &= Self::is_valid_protected_header(&self.protected_header);
            is_valid &= (1..16384).contains(&self.payload.len());
            is_valid &= self.signature.len() == 96;
            is_valid
        };
        if !is_valid {
            return Err(NitroError::InvalidCoseSign1);
        }
        Ok(())
    }

    fn is_valid_protected_header(bytes: &[u8]) -> bool {
        let signing_algorithm: Integer = Integer::from(1);
        let ecdsa_sha_384: Integer = Integer::from(-35);
        let value: Value = ciborium::de::from_reader(bytes).expect("valid cbor");
        match value {
            Value::Map(vec) => match &vec[..] {
                [(Value::Integer(key), Value::Integer(val))] => {
                    key == &signing_algorithm && val == &ecdsa_sha_384
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn to_canonical(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Text("Signature1".to_string()),
            Value::Bytes(self.protected_header.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut bytes = Vec::with_capacity(self.protected_header.len() + self.payload.len());
        ciborium::ser::into_writer(&value, &mut bytes).expect("can write bytes");
        bytes
    }
}

/// The AWS Nitro Attestation Document.
/// This is described in
/// https://docs.aws.amazon.com/ko_kr/enclaves/latest/user/verify-root.html
/// under the heading "Attestation document specification"
#[allow(dead_code)]
#[derive(Debug)]
struct AttestationDocument {
    module_id: String,
    timestamp: u64,
    digest: String,
    pcrs: Vec<Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl AttestationDocument {
    pub fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
        let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
            .map_err(|err| format!("document parse failed:{:?}", err))?;

        let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
            serde_cbor::Value::Map(map) => map,
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload field ain't what it should be:{:?}",
                    document_data
                ))
            }
        };

        let module_id: String =
            match document_map.get(&serde_cbor::Value::Text("module_id".to_string())) {
                Some(serde_cbor::Value::Text(val)) => val.to_string(),
                _ => {
                    return Err(
                        "AttestationDocument::parse_payload module_id is wrong type or not present"
                            .to_string(),
                    )
                }
            };

        let timestamp: i128 =
            match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
                Some(serde_cbor::Value::Integer(val)) => *val,
                _ => {
                    return Err(
                        "AttestationDocument::parse_payload timestamp is wrong type or not present"
                            .to_string(),
                    )
                }
            };

        let timestamp: u64 = timestamp.try_into().map_err(|err| {
            format!(
                "AttestationDocument::parse_payload failed to convert timestamp to u64:{:?}",
                err
            )
        })?;

        let public_key: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                Some(_null) => None,
                None => None,
            };

        let certificate: Vec<u8> =
            match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
                _ => return Err(
                    "AttestationDocument::parse_payload certificate is wrong type or not present"
                        .to_string(),
                ),
            };

        let pcrs: Vec<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("pcrs".to_string()))
        {
            Some(serde_cbor::Value::Map(map)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                let num_entries:i128 = map.len().try_into()
                    .map_err(|err| format!("AttestationDocument::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
                for x in 0..num_entries {
                    match map.get(&serde_cbor::Value::Integer(x)) {
                        Some(serde_cbor::Value::Bytes(inner_vec)) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err("AttestationDocument::parse_payload pcrs inner vec is wrong type or not there?".to_string()),
                    }
                }
                ret_vec
            }
            _ => {
                return Err(
                    "AttestationDocument::parse_payload pcrs is wrong type or not present"
                        .to_string(),
                )
            }
        };

        let nonce: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                None => None,
                _ => None,
            };

        let user_data: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                None => None,
                Some(_null) => None,
            };

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
        {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => {
                return Err(
                    "AttestationDocument::parse_payload digest is wrong type or not present"
                        .to_string(),
                )
            }
        };

        let cabundle: Vec<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
                Some(serde_cbor::Value::Array(outer_vec)) => {
                    let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                    for this_vec in outer_vec.iter() {
                        match this_vec {
                            serde_cbor::Value::Bytes(inner_vec) => {
                                ret_vec.push(inner_vec.to_vec());
                            }
                            _ => {
                                return Err(
                                    "AttestationDocument::parse_payload inner_vec is wrong type"
                                        .to_string(),
                                )
                            }
                        }
                    }
                    ret_vec
                }
                _ => {
                    return Err(format!(
                    "AttestationDocument::parse_payload cabundle is wrong type or not present:{:?}",
                    document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
                ))
                }
            };

        Ok(AttestationDocument {
            module_id,
            timestamp,
            digest,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }

    fn verified_cert(&self, now: SystemTime) -> Result<X509, NitroError> {
        let mut context = X509StoreContext::new()?;
        let certificate = X509::from_der(&self.certificate)?;
        let mut stack = stack::Stack::<X509>::new()?;
        for der in self.cabundle.iter() {
            let cert = X509::from_der(der)?;
            stack.push(cert)?;
        }
        let stack = stack;
        let trust = {
            let root = X509::from_pem(ROOT_CERTIFICATE_PEM)?;
            let mut builder = X509StoreBuilder::new()?;
            builder.param_mut().set_time(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("current time is after 1970")
                    .as_secs()
                    .try_into()
                    .expect("haven't yet overflowed time_t"),
            );
            builder.add_cert(root)?;
            builder.build()
        };
        let is_valid = context.init(&trust, &certificate, &stack, |ctx| ctx.verify_cert())?;
        if !is_valid {
            let message = context.verify_result().unwrap_err().to_string();
            return Err(NitroError::InvalidCertificate(message));
        }
        Ok(certificate)
    }

    fn validate_pcrs(&self, expected_pcrs: &[&[u8]]) -> Result<(), NitroError> {
        if expected_pcrs.len() != 3 {
            return Err(NitroError::InvalidPcrs);
        }
        let mut is_match = true;
        for (index, pcr) in self.pcrs.iter().enumerate() {
            is_match &= expected_pcrs
                .get(index)
                .map(|expected| expected.ct_eq(pcr).into())
                // if the index is missing from the expected_pcrs we do not check it
                .unwrap_or(true);
        }
        if is_match {
            Ok(())
        } else {
            Err(NitroError::InvalidPcrs)
        }
    }
}
