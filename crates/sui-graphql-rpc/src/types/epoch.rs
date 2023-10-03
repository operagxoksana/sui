// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::big_int::BigInt;
use super::date_time::DateTime;
use super::protocol_config::ProtocolConfigs;
use super::safe_mode::SafeMode;
use super::stake_subsidy::StakeSubsidy;
use super::storage_fund::StorageFund;
use super::system_parameters::SystemParameters;
use super::validator_set::ValidatorSet;
use async_graphql::*;
use sui_indexer::models_v2::epoch::StoredEpochInfo;

#[derive(Clone, Debug, PartialEq, Eq, SimpleObject)]
pub(crate) struct Epoch {
    pub epoch_id: u64,
    pub system_state_version: Option<BigInt>,
    pub protocol_configs: Option<ProtocolConfigs>, // TODO (wlmyng): This can now be resolved as StoredEpochInfo contains protocol_version info
    pub reference_gas_price: Option<BigInt>,
    pub system_parameters: Option<SystemParameters>,
    pub stake_subsidy: Option<StakeSubsidy>,
    pub validator_set: Option<ValidatorSet>,
    pub storage_fund: Option<StorageFund>,
    pub safe_mode: Option<SafeMode>,
    pub start_timestamp: Option<DateTime>,
    // pub end_timestamp: Option<DateTime>, //TODO decide if we want this data exposed or not
}

impl From<StoredEpochInfo> for Epoch {
    fn from(e: StoredEpochInfo) -> Self {
        Self {
            epoch_id: e.epoch as u64,
            system_state_version: None,
            protocol_configs: None,
            reference_gas_price: Some(BigInt::from(e.reference_gas_price as u64)),
            system_parameters: None,
            stake_subsidy: None,
            validator_set: None,
            storage_fund: None,
            safe_mode: None,
            start_timestamp: None,
        }
    }
}
