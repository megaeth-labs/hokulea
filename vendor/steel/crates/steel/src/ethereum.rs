// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Type aliases and specifications for Ethereum.
use crate::{
    config::{ChainSpec, ForkCondition},
    serde::RlpHeader,
    EvmBlockHeader, EvmEnv, EvmFactory, EvmInput, EvmSpecId,
};
use alloy_eips::{eip4844, eip7691};
use alloy_evm::{Database, EthEvmFactory as AlloyEthEvmFactory, EvmFactory as AlloyEvmFactory};
use alloy_primitives::{Address, BlockNumber, Bytes, TxKind, B256, U256};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};

/// The Ethereum Sepolia [ChainSpec].
pub static ETH_SEPOLIA_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 11155111,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(1735371)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1677557088)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1706655072)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1741159776)),
        (SpecId::OSAKA, ForkCondition::Timestamp(1760427360)),
        // Pinned geth 3d858f858a458effb2a563788aedf1fe65e1f0d3, params/config.go.
        (SpecId::AMSTERDAM, ForkCondition::Timestamp(1791294816)),
    ]),
});

/// The historical Ethereum Holešky [ChainSpec].
///
/// Holešky is retained because Hokulea supported chain 17000 before adopting this
/// newer Steel source. No post-Prague activation is invented for the sunset chain.
pub static ETH_HOLESKY_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 17000,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(0)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1696000704)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1707305664)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1740434112)),
    ]),
});

/// The Ethereum Hoodi [ChainSpec].
pub static ETH_HOODI_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 560048,
    forks: BTreeMap::from([
        (SpecId::CANCUN, ForkCondition::Block(0)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1742999832)),
        (SpecId::OSAKA, ForkCondition::Timestamp(1761677592)),
    ]),
});

/// The Ethereum Mainnet [ChainSpec].
pub static ETH_MAINNET_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 1,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(15537394)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1681338455)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1710338135)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1746612311)),
        (SpecId::OSAKA, ForkCondition::Timestamp(1764798551)),
    ]),
});

/// [ChainSpec] for a custom Steel Testnet using the Prague EVM.
pub static STEEL_TEST_PRAGUE_CHAIN_SPEC: LazyLock<ChainSpec<SpecId>> =
    LazyLock::new(|| ChainSpec::new_single(5733100018, SpecId::PRAGUE));

/// [EvmFactory] for Ethereum.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EthEvmFactory;

impl EvmFactory for EthEvmFactory {
    type Evm<DB: Database> = <AlloyEthEvmFactory as AlloyEvmFactory>::Evm<DB, NoOpInspector>;
    type Tx = <AlloyEthEvmFactory as AlloyEvmFactory>::Tx;
    type Error<DBError: revm::database::DBErrorMarker> =
        <AlloyEthEvmFactory as AlloyEvmFactory>::Error<DBError>;
    type HaltReason = <AlloyEthEvmFactory as AlloyEvmFactory>::HaltReason;
    type Spec = <AlloyEthEvmFactory as AlloyEvmFactory>::Spec;
    type SpecId = SpecId;
    type Header = EthBlockHeader;

    fn new_tx(address: Address, data: Bytes) -> Self::Tx {
        TxEnv {
            caller: address,
            kind: TxKind::Call(address),
            data,
            chain_id: None,
            ..Default::default()
        }
    }

    fn create_evm<DB: Database>(
        db: DB,
        chain_id: u64,
        spec_id: Self::SpecId,
        header: &Self::Header,
    ) -> Self::Evm<DB> {
        let mut cfg_env = CfgEnv::new_with_spec(spec_id).with_chain_id(chain_id);
        cfg_env.disable_nonce_check = true;
        cfg_env.disable_balance_check = true;
        cfg_env.disable_block_gas_limit = true;
        // Disabled because eth_call is sometimes used with eoa senders
        cfg_env.disable_eip3607 = true;
        // The basefee should be ignored for eth_call
        cfg_env.disable_base_fee = true;

        let mut block_env = header.to_block_env(spec_id);
        // BPO changes are timestamp schedules within Osaka, not separate EVM specs.
        // Apply them here because the header conversion alone has no chain identity.
        if spec_id >= SpecId::OSAKA {
            if let Some(fraction) = bpo_update_fraction(chain_id, header.timestamp()) {
                if let Some(excess) = header.inner().excess_blob_gas {
                    block_env.blob_excess_gas_and_price =
                        Some(BlobExcessGasAndPrice::new(excess, fraction));
                }
            }
        }

        AlloyEthEvmFactory::default().create_evm(db, (cfg_env, block_env).into())
    }
}

// Ethereum geth 3d858f858a458effb2a563788aedf1fe65e1f0d3, params/config.go.
// EIP-7918 affects excess evolution; the header's authenticated excess is used as-is.
fn bpo_update_fraction(chain_id: u64, timestamp: u64) -> Option<u64> {
    let (bpo1, bpo2) = match chain_id {
        1 => (1765290071, 1767747671),
        11155111 => (1761017184, 1761607008),
        _ => return None,
    };
    if timestamp >= bpo2 {
        Some(11_684_671)
    } else if timestamp >= bpo1 {
        Some(8_346_193)
    } else {
        None
    }
}

/// [ChainSpec] for Ethereum.
pub type EthChainSpec = ChainSpec<SpecId>;

/// [EvmEnv] for Ethereum.
pub type EthEvmEnv<D, C> = EvmEnv<D, EthEvmFactory, C>;

/// [EvmInput] for Ethereum.
pub type EthEvmInput = EvmInput<EthEvmFactory>;

/// [EvmBlockHeader] for Ethereum.
pub type EthBlockHeader = RlpHeader<alloy_consensus::Header>;

impl EvmSpecId for SpecId {
    #[inline]
    fn has_eip4788(&self) -> bool {
        self >= &SpecId::CANCUN
    }
    #[inline]
    fn has_eip2935(&self) -> bool {
        self >= &SpecId::PRAGUE
    }
    #[inline]
    fn to_u32(&self) -> u32 {
        *self as u32
    }
}

impl EvmBlockHeader for EthBlockHeader {
    type SpecId = SpecId;

    #[inline]
    fn parent_hash(&self) -> &B256 {
        &self.inner().parent_hash
    }
    #[inline]
    fn number(&self) -> BlockNumber {
        self.inner().number
    }
    #[inline]
    fn timestamp(&self) -> u64 {
        self.inner().timestamp
    }
    #[inline]
    fn state_root(&self) -> &B256 {
        &self.inner().state_root
    }
    #[inline]
    fn receipts_root(&self) -> &B256 {
        &self.inner().receipts_root
    }
    #[inline]
    fn logs_bloom(&self) -> &alloy_primitives::Bloom {
        &self.inner().logs_bloom
    }

    #[inline]
    fn to_block_env(&self, spec: SpecId) -> BlockEnv {
        let header = self.inner();

        let blob_excess_gas_and_price = header.excess_blob_gas.map(|excess_blob_gas| match spec {
            SpecId::CANCUN => BlobExcessGasAndPrice::new(
                excess_blob_gas,
                eip4844::BLOB_GASPRICE_UPDATE_FRACTION as u64,
            ),
            SpecId::PRAGUE => BlobExcessGasAndPrice::new(
                excess_blob_gas,
                eip7691::BLOB_GASPRICE_UPDATE_FRACTION_PECTRA as u64,
            ),
            SpecId::OSAKA | SpecId::AMSTERDAM => BlobExcessGasAndPrice::new(
                excess_blob_gas,
                eip7691::BLOB_GASPRICE_UPDATE_FRACTION_PECTRA as u64,
            ),
            _ => unimplemented!("unsupported spec with `excess_blob_gas`: {spec}"),
        });

        BlockEnv {
            number: U256::from(header.number),
            beneficiary: header.beneficiary,
            timestamp: U256::from(header.timestamp),
            gas_limit: header.gas_limit,
            basefee: header.base_fee_per_gas.unwrap_or_default(),
            difficulty: header.difficulty,
            prevrandao: (spec >= SpecId::MERGE).then_some(header.mix_hash),
            blob_excess_gas_and_price,
            slot_num: header.slot_number.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;

    use super::{
        ETH_HOODI_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC, ETH_SEPOLIA_CHAIN_SPEC,
        STEEL_TEST_PRAGUE_CHAIN_SPEC,
    };

    // NOTE: If these are updated here, make sure to update them in Steel.sol

    #[test]
    fn mainnet_spec_digest() {
        assert_eq!(
            ETH_MAINNET_CHAIN_SPEC.digest(),
            b256!("0x47dc59f84afd2e9e7a48c4012004ab7c77fbd9acf822bf1143b8442c6c8851d4")
        );
    }

    #[test]
    fn sepolia_spec_digest() {
        assert_eq!(
            ETH_SEPOLIA_CHAIN_SPEC.digest(),
            b256!("0x4c6a19fd3ca4a019f3ab60f4485b4f4043ad076070c9a5cc2d6381f817f5ee62")
        );
    }

    #[test]
    fn hoodi_spec_digest() {
        assert_eq!(
            ETH_HOODI_CHAIN_SPEC.digest(),
            b256!("0x34cb1defd939572b00439d2c13f93c033b82227067371c910ad104d527c78860")
        );
    }

    #[test]
    fn testnet_spec_digest() {
        assert_eq!(
            STEEL_TEST_PRAGUE_CHAIN_SPEC.digest(),
            b256!("0x33e32d9590cd4b168773ca27de65d535f2e744274b1437acb712dd4264f2eb87")
        );
    }
}
