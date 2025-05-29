use starknet::ContractAddress;

#[starknet::component]
mod MesonStatesComponent {
    use starknet::{
        ContractAddress, EthAddress, get_contract_address,
        contract_address::ContractAddressZeroable
    };
    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, IERC20DispatcherTrait
    };
    use meson_starknet::utils::MesonHelpers::{
        _poolTokenIndexFrom, _isCoreToken, _needAdjustAmount
    };

    #[storage]
    struct Storage {
        owner: ContractAddress,
        premiumManager: ContractAddress,
        balanceOfPoolToken: LegacyMap<u64, u256>,
        ownerOfPool: LegacyMap<u64, ContractAddress>,
        poolOfAuthorizedAddr: LegacyMap<ContractAddress, u64>,
        indexOfToken: LegacyMap<ContractAddress, u8>,
        tokenForIndex: LegacyMap<u8, ContractAddress>,
        postedSwaps: LegacyMap<
            u256, (u64, EthAddress, ContractAddress)
        >,  // Customized struct cannot be used as the value of LegacyMap
        lockedSwaps: LegacyMap<
            u256, (u64, u64, ContractAddress)
        >,  // Customized struct cannot be used as the value of LegacyMap
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // TODO: add events
    }

    #[generate_trait]       // Internal functions that can be used in son contracts
    impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn poolTokenBalance(
            self: @ComponentState<TContractState>, 
            token: ContractAddress,
            addr: ContractAddress
        ) -> u256 {
            let tokenIndex: u8 = self.indexOfToken.read(token);
            let poolIndex: u64 = self.poolOfAuthorizedAddr.read(addr);
            if poolIndex == 0 || tokenIndex == 0 {
                0
            } else {
                let poolTokenIndex: u64 = _poolTokenIndexFrom(tokenIndex, poolIndex);
                self.balanceOfPoolToken.read(poolTokenIndex)
            }
        }

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
                assert(token != ContractAddressZeroable::zero(), 'Token not supported');

                if _needAdjustAmount(tokenIndex) {
                    let amount = amount * 1_000000_000000;
                }

                IERC20Dispatcher { contract_address: token }.transfer_from(
                    sender, get_contract_address(), amount
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

                if _needAdjustAmount(tokenIndex) {
                    let amount = amount * 1_000000_000000;
                }

                IERC20Dispatcher { contract_address: token }.transfer(
                    recipient, amount
                );
            }
        }

        fn _addSupportToken(
            ref self: ComponentState<TContractState>,
            token: ContractAddress,
            index: u8
        ) {
            assert(index != 0, 'Cannot use 0 as token index');
            assert(token != ContractAddressZeroable::zero(), 'Cannot use zero address');
            assert(self.indexOfToken.read(token) == 0, 'Token has been added before');
            assert(
                self.tokenForIndex.read(index) == ContractAddressZeroable::zero(), 
                'Index has been used'
            );
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
            assert(token != ContractAddressZeroable::zero(), 'Token for this index not exist');
            self.indexOfToken.write(token, 0);
            self.tokenForIndex.write(index, ContractAddressZeroable::zero());
        }

        // _transferToContract: Don't need to write this function

        fn _transferOwnership(
            ref self: ComponentState<TContractState>,
            newOwner: ContractAddress
        ) {
            assert(
                newOwner != ContractAddressZeroable::zero(), 
                'New owner cannot be zero!'
            );
            self.owner.write(newOwner);
        }

        fn _transferPremiumManager(
            ref self: ComponentState<TContractState>,
            newPremiumManager: ContractAddress
        ) {
            assert(
                newPremiumManager != ContractAddressZeroable::zero(), 
                'New manager cannot be zero!'
            );
            self.premiumManager.write(newPremiumManager);
        }
    }

}