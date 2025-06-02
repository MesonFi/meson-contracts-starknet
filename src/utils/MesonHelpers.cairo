use core::{
    num::traits::Zero,
    option::OptionTrait,
    traits::TryInto,
    keccak::compute_keccak_byte_array,
};
use starknet::{
    ContractAddress, EthAddress,
    eth_signature::verify_eth_signature,
    secp256_trait::signature_from_vrs,
};
use alexandria_bytes::{Bytes, BytesTrait};
use meson_starknet::utils::MesonConstants;

// Note that there's no `<<` or `>>` operator in cairo.
const POW_2_255: u256 = 0x8000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000__0000__0000_0000;
const POW_2_248: u256 = 0x100_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const POW_2_208: u256 = 0x1_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const POW_2_172: u256 = 0x1000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const POW_2_160: u256 = 0x1_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const POW_2_128: u256 = 0x1_0000_0000_0000_0000_0000_0000_0000_0000;
const POW_2_96 : u256 = 0x1_0000_0000_0000_0000_0000_0000;
const POW_2_88 : u256 = 0x100_0000_0000_0000_0000_0000;
const POW_2_48 : u256 = 0x1_0000_0000_0000;
const POW_2_40 : u256 = 0x100_0000_0000;
const POW_2_32 : u256 = 0x1_0000_0000;
const POW_2_24 : u256 = 0x100_0000;
const POW_2_16 : u256 = 0x1_0000;
const POW_2_8  : u256 = 0x100;

const U160_MAX : u256 = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const U80_MAX  : u256 = 0xffff_ffff_ffff_ffff_ffff;
const U64_MAX  : u256 = 0xffff_ffff_ffff_ffff;
const U40_MAX  : u256 = 0xff_ffff_ffff;
const U32_MAX  : u256 = 0xffff_ffff;
const U20_MAX  : u256 = 0xf_ffff;
const U16_MAX  : u256 = 0xffff;
const U12_MAX  : u256 = 0xfff;
const U8_MAX   : u256 = 0xff;

enum MesonErrors {
    TokenIndexNotAllowed,
    SignerCannotBeZero,
    InvalidSignature,
}

pub(crate) fn _getSwapId(encodedSwap: u256, initiator: EthAddress) -> u256 {
    let mut bytes = BytesTrait::new_empty();
    bytes.append_u256(encodedSwap);
    let initiator_felt252: felt252 = initiator.into();
    let initiator_u256: u256 = initiator_felt252.into();
    bytes.append_u128_packed(initiator_u256.high, 4);
    bytes.append_u128(initiator_u256.low);
    compute_keccak_byte_array(@bytes.into())
}

pub(crate) fn _versionFrom(encodedSwap: u256) -> u8 {
    (encodedSwap / POW_2_248).try_into().unwrap()
}

pub(crate) fn _amountFrom(encodedSwap: u256) -> u256 {
    (encodedSwap / POW_2_208) & U40_MAX
}

pub(crate) fn _amountToLock(encodedSwap: u256) -> u256 {
    _amountFrom(encodedSwap) - _feeForLp(encodedSwap) - _amountForCoreTokenFrom(encodedSwap)
}

pub(crate) fn _serviceFee(encodedSwap: u256) -> u256 {
    let minFee = if _inTokenIndexFrom(encodedSwap) >= 191 {
        MesonConstants::SERVICE_FEE_MINIMUM_CORE
    } else {
        MesonConstants::SERVICE_FEE_MINIMUM
    };
    let fee = _amountFrom(encodedSwap) * MesonConstants::SERVICE_FEE_RATE / 10000;
    if fee > minFee {
        fee
    } else {
        minFee
    }
}

pub(crate) fn _feeForLp(encodedSwap: u256) -> u256 {
    (encodedSwap / POW_2_88) & U40_MAX
}

pub(crate) fn _saltFrom(encodedSwap: u256) -> u128 {    // Original uint256 -> uint80
    ((encodedSwap / POW_2_128) & U80_MAX).try_into().unwrap()
}

pub(crate) fn _saltDataFrom(encodedSwap: u256) -> u64 {
    ((encodedSwap / POW_2_128) & U64_MAX).try_into().unwrap()
}

pub(crate) fn _willTransferToContract(encodedSwap: u256) -> bool {
    (encodedSwap & 0x8000000000000000000000000000000000000000000000000000) == 0
}

pub(crate) fn _feeWaived(encodedSwap: u256) -> bool {
    (encodedSwap & 0x4000000000000000000000000000000000000000000000000000) > 0
}
  
pub(crate) fn _signNonTyped(encodedSwap: u256) -> bool {
    (encodedSwap & 0x0800000000000000000000000000000000000000000000000000) > 0
}

pub(crate) fn _isCoreToken(tokenIndex: u8) -> bool {
    (tokenIndex == 52) || ((tokenIndex > 190) && ((tokenIndex % 4) == 3))
}

pub(crate) fn _swapForCoreToken(encodedSwap: u256) -> bool {
    !_willTransferToContract(encodedSwap) && (_outTokenIndexFrom(encodedSwap) < 191) &&
        (encodedSwap & 0x0400000000000000000000000000000000000000000000000000 > 0)
}

pub(crate) fn _amountForCoreTokenFrom(encodedSwap: u256) -> u256 {
    if _swapForCoreToken(encodedSwap) {
        ((encodedSwap / POW_2_160) & U12_MAX) * 100000
    } else {
        0
    }
}

pub(crate) fn _coreTokenAmount(encodedSwap: u256) -> u256 {
    let amountForCore = _amountForCoreTokenFrom(encodedSwap);
    if amountForCore > 0 {
        amountForCore * MesonConstants::CORE_TOKEN_PRICE_FACTOR / 
            ((encodedSwap / POW_2_172) & U20_MAX)
    } else {
        0
    }
}

pub(crate) fn _expireTsFrom(encodedSwap: u256) -> u256 {
    (encodedSwap / POW_2_48) & U40_MAX
}

pub(crate) fn _inChainFrom(encodedSwap: u256) -> u16 {
    ((encodedSwap / POW_2_8) & U16_MAX).try_into().unwrap()
}

pub(crate) fn _inTokenIndexFrom(encodedSwap: u256) -> u8 {
    (encodedSwap & U8_MAX).try_into().unwrap()
}

pub(crate) fn _outChainFrom(encodedSwap: u256) -> u16 {
    ((encodedSwap / POW_2_32) & U16_MAX).try_into().unwrap()
}

pub(crate) fn _outTokenIndexFrom(encodedSwap: u256) -> u8 {
    ((encodedSwap / POW_2_24) & U8_MAX).try_into().unwrap()
}

pub(crate) fn _tokenType(tokenIndex: u8) -> u8 {
    if tokenIndex >= 192 {
        // Non stablecoins [192, 255] -> [48, 63]
        tokenIndex / 4
    } else if tokenIndex <= 64 {
        // Stablecoins [1, 64] -> 0
        0
    } else if tokenIndex <= 112 {
        // 3rd party tokens [65, 112] -> [1, 24]
        (tokenIndex + 1) / 2 - 32
    } else if tokenIndex <= 128 {
        // 3rd party tokens [113, 128] -> [33, 48]
        tokenIndex - 80
    } else {
        assert(false, 'Token index not allowed!');
        0
    }
}

pub(crate) fn _poolTokenIndexForOutToken(encodedSwap: u256, poolIndex: u64) -> u64 {
    ((encodedSwap & 0xFF000000) * POW_2_16).try_into().unwrap() | poolIndex
}

pub(crate) fn _initiatorFromPosted(postedSwap: u256) -> EthAddress {
    ((postedSwap / POW_2_40) & U160_MAX).into()
}

pub(crate) fn _poolIndexFromPosted(postedSwap: u256) -> u64 {
    (postedSwap & U40_MAX).try_into().unwrap()
}

// pub(crate) fn _lockedSwapFrom(until: u256, poolIndex: u64) -> u128 {   // original (uint256, uint40) -> uint80
//     ((until * POW_2_40).try_into().unwrap() | poolIndex).into()
// }

// pub(crate) fn _poolIndexFromLocked(lockedSwap: u128) -> u64 {  // original (uint80) -> uint40
//     (lockedSwap.into() & U40_MAX).try_into().unwrap()
// }

// pub(crate) fn _untilFromLocked(lockedSwap: u128) -> u256 {  // original (uint80) -> uint256
//     (lockedSwap.into() / POW_2_40).into()
// }

pub(crate) fn _poolTokenIndexFrom(tokenIndex: u8, poolIndex: u64) -> u64 {     // original (uint8, uint40) -> uint48
    (tokenIndex.into() * POW_2_40).try_into().unwrap() | poolIndex
}

pub(crate) fn _tokenIndexFrom(poolTokenIndex: u64) -> u8 {     // original (uint48) -> uint8
    (poolTokenIndex.into() / POW_2_40).try_into().unwrap()
}

pub(crate) fn _poolIndexFrom(poolTokenIndex: u64) -> u64 {     // original (uint48) -> uint40
    (poolTokenIndex.into() & U40_MAX).try_into().unwrap()
}

pub(crate) fn _ethAddressFromStarknet(starknetAddress: ContractAddress) -> EthAddress {
    let starknetAddressFelt252: felt252 = starknetAddress.into();
    let starknetAddressU256: u256 = starknetAddressFelt252.into();
    (starknetAddressU256 / POW_2_96).into()
}

pub(crate) fn _checkRequestSignature(
    encodedSwap: u256,
    r: u256,
    yParityAndS: u256,
    signer: EthAddress,
) {
    let nonTyped = _signNonTyped(encodedSwap);

    let signingData = if _inChainFrom(encodedSwap) == 0x00c3 {
        let mut bytes: Bytes = if nonTyped {
            MesonConstants::TRON_SIGN_HEADER_33()
        } else {
            MesonConstants::TRON_SIGN_HEADER()
        }.into();
        bytes.append_u256(encodedSwap);
        bytes
    } else if nonTyped {
        let mut bytes: Bytes = MesonConstants::ETH_SIGN_HEADER().into();
        bytes.append_u256(encodedSwap);
        bytes
    } else {
        let mut msgHashBytes = BytesTrait::new_empty();
        msgHashBytes.append_u256(encodedSwap);
        let msgHash = compute_keccak_byte_array(@msgHashBytes.into());
        let bytes = BytesTrait::new(64, array![
            MesonConstants::REQUEST_TYPE_HASH.high,
            MesonConstants::REQUEST_TYPE_HASH.low,
            msgHash.high, 
            msgHash.low,
        ]);
        bytes
    };

    let digest = compute_keccak_byte_array(@signingData.into());
    _checkSignature(digest, r, yParityAndS, signer);
}

pub(crate) fn _checkReleaseSignature(
    encodedSwap: u256,
    recipient: EthAddress,
    r: u256,
    yParityAndS: u256,
    signer: EthAddress,
) {
    let nonTyped = _signNonTyped(encodedSwap);
    let recipient_felt252: felt252 = recipient.into();
    let recipient_u256: u256 = recipient_felt252.into();

    let signingData = if _inChainFrom(encodedSwap) == 0x00c3 {
        let mut bytes: Bytes = if nonTyped {
            MesonConstants::TRON_SIGN_HEADER_53()
        } else {
            MesonConstants::TRON_SIGN_HEADER()
        }.into();
        bytes.append_u256(encodedSwap);
        bytes.append_u128_packed(recipient_u256.high, 4);
        bytes.append_u128(recipient_u256.low);
        bytes
    } else if nonTyped {
        let mut bytes: Bytes = MesonConstants::ETH_SIGN_HEADER_52().into();
        bytes.append_u256(encodedSwap);
        bytes.append_u128_packed(recipient_u256.high, 4);
        bytes.append_u128(recipient_u256.low);
        bytes
    } else {
        let mut msgHashBytes = BytesTrait::new_empty();
        msgHashBytes.append_u256(encodedSwap);
        msgHashBytes.append_u128_packed(recipient_u256.high, 4);
        msgHashBytes.append_u128(recipient_u256.low);
        let msgHash = compute_keccak_byte_array(@msgHashBytes.into());
        let typeHash = if _outChainFrom(encodedSwap) == 0x00c3 {
            MesonConstants::RELEASE_TO_TRON_TYPE_HASH
        } else {
            MesonConstants::RELEASE_TYPE_HASH
        };
        let bytes = BytesTrait::new(64, array![
            typeHash.high, typeHash.low,
            msgHash.high, msgHash.low,
        ]);
        bytes
    };
    
    let digest = _reverseU256(compute_keccak_byte_array(@signingData.into()));
    _checkSignature(digest, r, yParityAndS, signer);
}

fn _reverseU256(mut origin: u256) -> u256 {
    let mut reverse: u256 = 0;
    let mut i: u8 = 0;
    while i != 32 {
        let byte = origin & 0xff;
        reverse = reverse * 0x100 + byte;
        origin = origin / 0x100;
        i += 1;
    }
    reverse
}

pub(crate) fn _checkSignature(digest: u256, r: u256, yParityAndS: u256, signer: EthAddress) {
    let s = yParityAndS & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    let v: u32 = (yParityAndS / POW_2_255).try_into().unwrap() + 27;

    assert(signer.is_non_zero(), 'Signer cannot be zero!');
    assert(
        s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
        'Invalid signature!'    
    );

    let signature = signature_from_vrs(v, r, s);
    verify_eth_signature(digest, signature, signer);
}

#[test]
#[available_gas(50000000)]
fn test_check_signature() {
    let encoded_swap = 0x0100000f4240d80000000000c127fdf300000000000068320479232c0202ca22;
    let r = 0x23e57dfe5c345300a3d591a2017635f2315c6f1fb2a3dd2ae7bee6f2ad6408e7;
    let yParityAndS = 0x5882f43d9a944cc9cf227f74b2f0d330d6da8695d2119ef9f00ce0cbb3ccc49a;
    let initiator: EthAddress = 0xdc7ac7c33107f1876aec2d1d80764d06beec3984_u256.into();
    let recipient: ContractAddress = 0x01495a6d83bb1d35ac6e84922e9294ba2379b8b35140b66d6e09f58c15f64d6a
        .try_into().unwrap();
    let recipientAsEth: EthAddress = _ethAddressFromStarknet(recipient);
    _checkReleaseSignature(encoded_swap, recipientAsEth, r, yParityAndS, initiator);
}