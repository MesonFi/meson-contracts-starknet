// Constant values used in the Meson protocol.
pub const MESON_PROTOCOL_VERSION: u8 = 1;

// See https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const SHORT_COIN_TYPE: u16 = 0x232c;

pub const MAX_SWAP_AMOUNT: u256 = 100_000_000_000; // 100,000.000000 = 100k
pub const SERVICE_FEE_RATE: u256 = 5; // service fee = 5 / 10000 = 0.05%
pub const SERVICE_FEE_MINIMUM: u256 = 500_000; // min $0.5
pub const SERVICE_FEE_MINIMUM_CORE: u256 = 500; // min 0.0005 ETH ~ $1

pub const MIN_BOND_TIME_PERIOD: u256 = 1 * 60 * 60; // 1 hours
pub const MAX_BOND_TIME_PERIOD: u256 = 2 * 60 * 60; // 2 hours
pub const LOCK_TIME_PERIOD: u256 = 20 * 60; // 20 minutes

// keccak256 value for "bytes32 Sign to request a swap on Meson"
pub const REQUEST_TYPE_HASH: u256 = 0x9862d877599564bcd97c37305a7b0fdbe621d9c2a125026f2ad601f754a75abc;
// keccak256 value for "bytes32 Sign to release a swap on Mesonaddress Recipient"
pub const RELEASE_TYPE_HASH: u256 = 0x743e50106a7f059b52151dd4ba27a5f6c87b925ddfbdcf1c332e800da4b3df92;
// keccak256 value for "bytes32 Sign to release a swap on Mesonaddress Recipient (tron address in hex format)"
pub const RELEASE_TO_TRON_TYPE_HASH: u256 = 0x28cf5b919ed55db2b14d9e8b261a523eafb98bab117d3a8a56e559791415d17c;

// // (testnet) keccak256 value for "bytes32 Sign to request a swap on Meson (Testnet)"
// pub const REQUEST_TYPE_HASH: u256 = 0x7b521e60f64ab56ff03ddfb26df49be54b20672b7acfffc1adeb256b554ccb25;
// // (testnet) keccak256 value for "bytes32 Sign to release a swap on Meson (Testnet)address Recipient"
// pub const RELEASE_TYPE_HASH: u256 = 0xd23291d9d999318ac3ed13f43ac8003d6fbd69a4b532aeec9ffad516010a208c;
// // (testnet) keccak256 value for "bytes32 Sign to release a swap on Meson (Testnet)address Recipient (tron address in hex format)"
// pub const RELEASE_TO_TRON_TYPE_HASH: u256 = 0xd4786e314a149e139351cd038cade52355604bd9190780c901fd5733336bffbd;

pub fn ETH_SIGN_HEADER() -> ByteArray {
    "\x19Ethereum Signed Message:\n32"
}

pub fn ETH_SIGN_HEADER_52() -> ByteArray {
    "\x19Ethereum Signed Message:\n52"
}

pub fn TRON_SIGN_HEADER() -> ByteArray {
    "\x19TRON Signed Message:\n32\n"
}

pub fn TRON_SIGN_HEADER_33() -> ByteArray {
    "\x19TRON Signed Message:\n33\n"
}

pub fn TRON_SIGN_HEADER_53() -> ByteArray {
    "\x19TRON Signed Message:\n53\n"
}
