// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module sui::attestation;

/// @param attestation: attesttaion documents bytes data. 
/// @param enclave_pk: public key from enclave
///
/// If the attestation verifies against the pcrs and against the root of trust, also the user_data equals to attestation document's user data, return yes.
public native fun nitro_attestation_verify(
    attestation: &vector<u8>,
    enclave_pk: &vector<u8>,
    pcr0: &vector<u8>,
    pcr1: &vector<u8>,
    pcr2: &vector<u8>,
): bool;

// public native fun tpm2_attestation_verify(
//     user_data: &vector<u8>,
//     attestation: &vector<u8>,
// ): bool;
