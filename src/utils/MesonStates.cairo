#[starknet::component]
pub mod MesonStatesComponent {
    use core::num::traits::Zero;
    use starknet::{
        ContractAddress, EthAddress, get_contract_address,
        storage::{
            StoragePointerWriteAccess, Map, 
            StorageMapReadAccess, StorageMapWriteAccess,
        },
    };
    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, IERC20DispatcherTrait
    };
    use meson_starknet::utils::MesonHelpers::{
        _isCoreToken, _needAdjustAmount
    };

    #[storage]
    pub struct Storage {
        pub owner: ContractAddress,
        pub premiumManager: ContractAddress,
        pub balanceOfPoolToken: Map<u64, u256>,
        pub ownerOfPool: Map<u64, ContractAddress>,
        pub poolOfAuthorizedAddr: Map<ContractAddress, u64>,
        pub indexOfToken: Map<ContractAddress, u8>,
        pub tokenForIndex: Map<u8, ContractAddress>,
        pub postedSwaps: Map<
            u256, (u64, EthAddress, ContractAddress)
        >,  // Customized struct cannot be used as the value of Map
        pub lockedSwaps: Map<
            u256, (u64, u64, ContractAddress)
        >,  // Customized struct cannot be used as the value of Map
    }

    #[generate_trait]       // Internal functions that can be used in son contracts
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn _depositToken(
            ref self: ComponentState<TContractState>,
            tokenIndex: u8,
            sender: ContractAddress,
            amount: u256
        ) {
            assert(amount > 0, 'Amount must > 0');
            if _isCoreToken(tokenIndex) {
                // Core tokens (e.g. ETH or BNB)
                // TODO: how to check this?
                // assert(amount * 1e12 == msg.value, "msg.value does not match the amount");
            } else {
                // Stablecoins
                let token: ContractAddress = self.tokenForIndex.read(tokenIndex);
                assert(token.is_non_zero(), 'Token not supported');

                let mut adjustedAmount = amount;
                if _needAdjustAmount(tokenIndex) {
                    adjustedAmount = amount * 1_000000_000000;
                }

                IERC20Dispatcher { contract_address: token }.transfer_from(
                    sender, get_contract_address(), adjustedAmount
                );
            }
        }

        fn _safeTransfer(
            ref self: ComponentState<TContractState>,
            tokenIndex: u8,
            recipient: ContractAddress,
            amount: u256
        ) {
            if _isCoreToken(tokenIndex) {
                // Core tokens (e.g. ETH or BNB)
                // TODO
            } else {
                // Stablecoins
                let token: ContractAddress = self.tokenForIndex.read(tokenIndex);

                let mut adjustedAmount = amount;
                if _needAdjustAmount(tokenIndex) {
                    adjustedAmount = amount * 1_000000_000000;
                }

                IERC20Dispatcher { contract_address: token }.transfer(
                    recipient, adjustedAmount
                );
            }
        }

        fn _addSupportToken(
            ref self: ComponentState<TContractState>,
            token: ContractAddress,
            index: u8
        ) {
            assert(index != 0, 'Cannot use 0 as token index');
            assert(token.is_non_zero(), 'Cannot use zero address');
            assert(self.indexOfToken.read(token) == 0, 'Token has been added before');
            assert(self.tokenForIndex.read(index).is_zero(), 'Index has been used');
            if _isCoreToken(index) {
                // TODO: how to check this
                //     assert(
                //          token == ContractAddressZeroable::zero(), 
                //          "Core token requires adddress(0x1)"
                //     );
            }
            self.indexOfToken.write(token, index);
            self.tokenForIndex.write(index, token);
        }

        fn _removeSupportToken(
            ref self: ComponentState<TContractState>,
            index: u8
        ) {
            assert(index != 0, 'Cannot use 0 as token index');
            let token: ContractAddress = self.tokenForIndex.read(index);
            assert(token.is_non_zero(), 'Token for this index not exist');
            self.indexOfToken.write(token, 0);
            self.tokenForIndex.write(index, 0_felt252.try_into().unwrap());
        }

        // _transferToContract: Don't need to write this function

        fn _transferOwnership(
            ref self: ComponentState<TContractState>,
            newOwner: ContractAddress
        ) {
            assert(newOwner.is_non_zero(), 'New owner cannot be zero!');
            self.owner.write(newOwner);
        }

        fn _transferPremiumManager(
            ref self: ComponentState<TContractState>,
            newPremiumManager: ContractAddress
        ) {
            assert(newPremiumManager.is_non_zero(), 'New manager cannot be zero!');
            self.premiumManager.write(newPremiumManager);
        }
    }

}