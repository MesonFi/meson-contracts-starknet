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
    use meson_starknet::utils::MesonHelpers::_isCoreToken;

    #[storage]
    pub struct Storage {
        pub owner: ContractAddress,
        pub premiumManager: ContractAddress,
        pub tokenForIndex: Map<u8, ContractAddress>,
        pub indexOfToken: Map<ContractAddress, u8>,
        pub poolOfAuthorizedAddr: Map<ContractAddress, u64>,
        pub ownerOfPool: Map<u64, ContractAddress>,
        pub balanceOfPoolToken: Map<u64, u256>,
        pub postedSwaps: Map<u256, (u64, EthAddress, ContractAddress)>,
        pub lockedSwaps: Map<u256, (u64, u64, ContractAddress)>,
    }

    #[generate_trait]       // Internal functions that can be used in son contracts
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {

        fn _transferOwnership(
            ref self: ComponentState<TContractState>,
            newOwner: ContractAddress
        ) {
            assert(newOwner.is_non_zero(), 'New owner cannot be zero');
            self.owner.write(newOwner);
        }

        fn _transferPremiumManager(
            ref self: ComponentState<TContractState>,
            newPremiumManager: ContractAddress
        ) {
            assert(newPremiumManager.is_non_zero(), 'New premium manager cannot be zero');
            self.premiumManager.write(newPremiumManager);
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
            assert(!self._isCoreToken(index), 'Core token not supported');
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

        fn _depositToken(
            ref self: ComponentState<TContractState>,
            tokenIndex: u8,
            sender: ContractAddress,
            amount: u256
        ) {
            assert(amount > 0, 'Amount cannot be 0');
            assert(!self._isCoreToken(tokenIndex), 'Core token not supported');

            let token: ContractAddress = self.tokenForIndex.read(tokenIndex);
            assert(token.is_non_zero(), 'Token not supported');

            IERC20Dispatcher { contract_address: token }.transfer_from(
                sender, get_contract_address(), amount * self._amountFactor(tokenIndex)
            );
        }

        fn _withdrawToken(
            ref self: ComponentState<TContractState>,
            tokenIndex: u8,
            recipient: ContractAddress,
            amount: u256
        ) {
            assert(amount > 0, 'Amount cannot be 0');
            assert(!self._isCoreToken(tokenIndex), 'Core token not supported');

            let token: ContractAddress = self.tokenForIndex.read(tokenIndex);
            assert(token.is_non_zero(), 'Token not supported');

            IERC20Dispatcher { contract_address: token }.transfer(
                recipient, amount * self._amountFactor(tokenIndex)
            );
        }

        fn _isCoreToken(tokenIndex: u8) -> bool {
            (tokenIndex >= 49 && tokenIndex <= 64) || ((tokenIndex > 190) && ((tokenIndex % 4) == 3))
        }

        fn _amountFactor(
            ref self: ComponentState<TContractState>,
            tokenIndex: u8
        ) -> u256 {
            if tokenIndex <= 32 {
                1
            } else if tokenIndex == 242 {
                100
            } else if tokenIndex > 112 && tokenIndex <= 123 {
                100
            } else if tokenIndex > 123 && tokenIndex <= 128 {
                1000
            } else {
                1_0000_0000_0000
            }
        }
    }

}