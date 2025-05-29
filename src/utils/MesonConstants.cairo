// Constant values used in the Meson protocol.
use alexandria_bytes::{Bytes, BytesTrait};

const MESON_PROTOCOL_VERSION: u8 = 1;

// See https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const SHORT_COIN_TYPE: u16 = 0x232c;

const MAX_SWAP_AMOUNT: u256 = 100_000_000_000; // 100,000.000000 = 100k
const SERVICE_FEE_RATE: u256 = 5; // service fee = 5 / 10000 = 0.05%
const SERVICE_FEE_MINIMUM: u256 = 500_000; // min $0.5
const SERVICE_FEE_MINIMUM_CORE: u256 = 500; // min 0.0005 ETH ~ $1

const CORE_TOKEN_PRICE_FACTOR: u256 = 10;

const MIN_BOND_TIME_PERIOD: u256 = consteval_int!(1 * 60 * 60); // 1 hours
const MAX_BOND_TIME_PERIOD: u256 = consteval_int!(2 * 60 * 60); // 2 hours
const LOCK_TIME_PERIOD: u256 = consteval_int!(40 * 60); // 40 minutes

const ETH_SIGN_HEADER: felt252= '\x19Ethereum Signed Message:\n32';     // length=28
const ETH_SIGN_HEADER_52: felt252 = '\x19Ethereum Signed Message:\n52'; // length=28
const TRON_SIGN_HEADER: felt252 = '\x19TRON Signed Message:\n32\n';     // length=25
const TRON_SIGN_HEADER_33: felt252 = '\x19TRON Signed Message:\n33\n';  // length=25
const TRON_SIGN_HEADER_53: felt252 = '\x19TRON Signed Message:\n53\n';  // length=25

// Note that this is for the testnet only!
// keccak256 value for "bytes32 Sign to request a swap on Meson (Testnet)"
const REQUEST_TYPE_HASH: u256 = 0x7b521e60f64ab56ff03ddfb26df49be54b20672b7acfffc1adeb256b554ccb25;
// keccak256 value for "bytes32 Sign to request a swap on Meson (Testnet)address Recipient"
const RELEASE_TYPE_HASH: u256 = 0xd23291d9d999318ac3ed13f43ac8003d6fbd69a4b532aeec9ffad516010a208c;
// keccak256 value for "bytes32 Sign to release a swap on Mesonaddress Recipient (tron address in hex format)"
const RELEASE_TO_TRON_TYPE_HASH: u256 = 0x28cf5b919ed55db2b14d9e8b261a523eafb98bab117d3a8a56e559791415d17c;

fn _getEthSignHeaderBytes(is32: bool) -> Bytes {
    let mut bytes = BytesTrait::new_empty();
    let header: u256 = (if is32 { ETH_SIGN_HEADER } else { ETH_SIGN_HEADER_52 }).into();
    bytes.append_u128_packed(header.high, 12);
    bytes.append_u128(header.low);
    bytes
}

fn _getTronSignHeaderBytes(is32: bool, is33: bool) -> Bytes {
    let mut bytes = BytesTrait::new_empty();
    let header: u256 = (if is32 { TRON_SIGN_HEADER } else 
        if is33 { TRON_SIGN_HEADER_33 } else { TRON_SIGN_HEADER_53 }).into();
    bytes.append_u128_packed(header.high, 9);
    bytes.append_u128(header.low);
    bytes
}
