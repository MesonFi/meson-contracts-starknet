#[starknet::contract]
mod Meson {
    use core::num::traits::Zero;
    use starknet::{
        EthAddress, ContractAddress, ClassHash,
        get_caller_address, get_block_timestamp,
        storage::{
            StoragePointerWriteAccess, StoragePointerReadAccess,
            StorageMapReadAccess, StorageMapWriteAccess,
        },
    };
    use openzeppelin::upgrades::{interface::IUpgradeable, UpgradeableComponent};
    use meson_starknet::interface::{
        MesonViewStorageTrait, MesonManagerTrait, MesonSwapTrait, MesonPoolsTrait
    };
    use meson_starknet::utils::{
        MesonConstants, MesonHelpers, MesonStates::MesonStatesComponent,
    };
    use meson_starknet::events;

    component!(path: MesonStatesComponent, storage: storage, event: MesonEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    impl MesonInternalImpl = MesonStatesComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[nested(v0)]
        #[substorage(v0)]
        storage: MesonStatesComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        MesonEvent: MesonStatesComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,

        PremiumManagerTransferred: events::PremiumManagerTransferred,
        PoolRegistered: events::PoolRegistered,
        PoolAuthorizedAddrAdded: events::PoolAuthorizedAddrAdded,
        PoolAuthorizedAddrRemoved: events::PoolAuthorizedAddrRemoved,
        PoolOwnerTransferred: events::PoolOwnerTransferred,
        PoolDeposited: events::PoolDeposited,
        PoolWithdrawn: events::PoolWithdrawn,
        SwapPosted: events::SwapPosted,
        SwapBonded: events::SwapBonded,
        SwapCancelled: events::SwapCancelled,
        SwapExecuted: events::SwapExecuted,
        SwapLocked: events::SwapLocked,
        SwapUnlocked: events::SwapUnlocked,
        SwapReleased: events::SwapReleased,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.storage.owner.write(owner);
        self.storage.premiumManager.write(owner);
        self.emit(events::PremiumManagerTransferred {
            prevPremiumManager: 0.try_into().unwrap(),
            newPremiumManager: owner,
        });
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.onlyOwner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    #[abi(embed_v0)]
    impl MesonViewStorage of MesonViewStorageTrait<ContractState> {

        // View functions
        fn getOwner(self: @ContractState) -> ContractAddress {
            self.storage.owner.read()
        }

        fn getPremiumManager(self: @ContractState) -> ContractAddress {
            self.storage.premiumManager.read()
        }

        fn tokenForIndex(self: @ContractState, index: u8) -> ContractAddress {
            self.storage.tokenForIndex.read(index)
        }

        fn indexOfToken(self: @ContractState, token: ContractAddress) -> u8 {
            self.storage.indexOfToken.read(token)
        }

        fn poolOfAuthorizedAddr(self: @ContractState, addr: ContractAddress) -> u64 {
            self.storage.poolOfAuthorizedAddr.read(addr)
        }

        fn ownerOfPool(self: @ContractState, poolIndex: u64) -> ContractAddress {
            self.storage.ownerOfPool.read(poolIndex)
        }

        fn poolTokenBalance(
            self: @ContractState,
            token: ContractAddress,
            addr: ContractAddress
        ) -> u256 {
            let tokenIndex: u8 = self.storage.indexOfToken.read(token);
            let poolIndex: u64 = self.storage.poolOfAuthorizedAddr.read(addr);
            if poolIndex == 0 || tokenIndex == 0 {
                0
            } else {
                let poolTokenIndex: u64 = MesonHelpers::_poolTokenIndexFrom(tokenIndex, poolIndex);
                self.storage.balanceOfPoolToken.read(poolTokenIndex)
            }
        }

        fn serviceFeeCollected(
            self: @ContractState,
            tokenIndex: u8
        ) -> u256 {
            let poolTokenIndex: u64 = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 0);
            self.storage.balanceOfPoolToken.read(poolTokenIndex)
        }

        fn getPostedSwap(self: @ContractState, encodedSwap: u256) -> (u64, EthAddress, ContractAddress) {
            self.storage.postedSwaps.read(encodedSwap)
        }

        fn getLockedSwap(self: @ContractState, swapId: u256) -> (u64, u64, ContractAddress) {
            self.storage.lockedSwaps.read(swapId)
        }

    }

    #[abi(embed_v0)]
    impl MesonManager of MesonManagerTrait<ContractState> {

        // View functions
        fn getShortCoinType(self: @ContractState) -> u16 {
            MesonConstants::SHORT_COIN_TYPE
        }

        fn getSupportedTokens(self: @ContractState) -> (Array<ContractAddress>, Array<u8>) {
            // TODO: test this function
            let mut tokens: Array<ContractAddress> = array![];
            let mut tokenIndexes: Array<u8> = array![];
            let mut i = 1;
            loop {
                let token = self.storage.tokenForIndex.read(i);
                if token.is_non_zero() {
                    tokens.append(token);
                    tokenIndexes.append(i);
                }
                if i == 255 {
                    break;
                }
                i += 1;
            };
            (tokens, tokenIndexes)
        }

        // Modifier
        fn onlyOwner(self: @ContractState) {
            assert(
                get_caller_address() == self.storage.owner.read(), 'Only for owner'
            );
        }

        fn onlyPremiumManager(self: @ContractState) {
            assert(
                get_caller_address() == self.storage.premiumManager.read(),
                'Only for premium manager'
            );
        }

        // Write functions
        fn transferOwnership(ref self: ContractState, newOwner: ContractAddress) {
            self.onlyOwner();
            self.storage._transferOwnership(newOwner);
        }

        fn transferPremiumManager(ref self: ContractState, newPremiumManager: ContractAddress) {
            self.onlyPremiumManager();
            self.storage._transferPremiumManager(newPremiumManager);
            self.emit(events::PremiumManagerTransferred {
                prevPremiumManager: get_caller_address(),
                newPremiumManager,
            });
        }

        fn addSupportToken(ref self: ContractState, token: ContractAddress, index: u8) {
            self.onlyOwner();
            self.storage._addSupportToken(token, index);
        }

        fn removeSupportToken(ref self: ContractState, index: u8) {
            self.onlyOwner();
            self.storage._removeSupportToken(index);
        }

        fn withdrawServiceFee(
            ref self: ContractState, tokenIndex: u8, amount: u256, toPoolIndex: u64
        ) {
            self.onlyOwner();
            assert(
                self.storage.ownerOfPool.read(toPoolIndex).is_non_zero(),
                'Pool index not registered'
            );
            let poolFrom = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 0);
            let poolTo = MesonHelpers::_poolTokenIndexFrom(tokenIndex, toPoolIndex);
            self.storage.balanceOfPoolToken.write(
                poolFrom, self.storage.balanceOfPoolToken.read(poolFrom) - amount
            );
            self.storage.balanceOfPoolToken.write(
                poolTo, self.storage.balanceOfPoolToken.read(poolTo) + amount
            );
        }

    }

    #[abi(embed_v0)]
    impl MesonSwap of MesonSwapTrait<ContractState> {

        // Modifier
        fn verifyEncodedSwap(self: @ContractState, encodedSwap: u256) {
            assert(
                MesonHelpers::_versionFrom(encodedSwap) == MesonConstants::MESON_PROTOCOL_VERSION,
                'Incorrect encoding version'
            );

            assert(
                MesonHelpers::_inChainFrom(encodedSwap) == MesonConstants::SHORT_COIN_TYPE,
                'Swap not for this chain'
            );
            assert(
                MesonHelpers::_tokenType(MesonHelpers::_inTokenIndexFrom(encodedSwap)) ==
                MesonHelpers::_tokenType(MesonHelpers::_outTokenIndexFrom(encodedSwap)),
                'In & out token types not match'
            );

            let (poolIndex, initiator, _) = self.getPostedSwap(encodedSwap);
            assert(poolIndex == 0 && initiator.is_zero(), 'Swap already exists');

            assert(
                MesonHelpers::_amountFrom(encodedSwap) <= MesonConstants::MAX_SWAP_AMOUNT,
                'Swap amount > 100k'
            );

            let delta = MesonHelpers::_expireTsFrom(encodedSwap) - get_block_timestamp().into();
            assert(delta > MesonConstants::MIN_BOND_TIME_PERIOD, 'Expire ts too early');
            assert(delta < MesonConstants::MAX_BOND_TIME_PERIOD, 'Expire ts too late');
        }

        // Write functions
        fn postSwapFromInitiator(ref self: ContractState, encodedSwap: u256, postingValue: u256) {
            self.verifyEncodedSwap(encodedSwap);

            let initiator = MesonHelpers::_initiatorFromPosted(postingValue);
            let poolIndex = MesonHelpers::_poolIndexFromPosted(postingValue);
            let fromAddress = get_caller_address();
            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, fromAddress));

            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            self.storage._depositToken(tokenIndex, fromAddress, MesonHelpers::_amountFrom(encodedSwap));

            self.emit(events::SwapPosted { encodedSwap });
        }

        fn bondSwap(ref self: ContractState, encodedSwap: u256, poolIndex: u64) {
            let (poolIndex, initiator, fromAddress) = self.getPostedSwap(encodedSwap);
            assert(fromAddress.is_non_zero(), 'Swap does not exist');
            assert(poolIndex == 0, 'Swap bonded to others');

            let callerAddress = get_caller_address();
            assert(
                self.storage.poolOfAuthorizedAddr.read(callerAddress) == poolIndex,
                'Not authorized address'
            );

            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, fromAddress));

            self.emit(events::SwapBonded { encodedSwap });
        }

        fn cancelSwap(ref self: ContractState, encodedSwap: u256) {
            let (_, _, fromAddress) = self.getPostedSwap(encodedSwap);
            assert(fromAddress.is_non_zero(), 'Swap does not exist');
            assert(
                MesonHelpers::_expireTsFrom(encodedSwap) < get_block_timestamp().into(),
                'Swap is still locked'
            );

            self.storage.postedSwaps.write(encodedSwap, (0, 0.try_into().unwrap(), 0_felt252.try_into().unwrap()));

            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            self.storage._withdrawToken(tokenIndex, fromAddress, MesonHelpers::_amountFrom(encodedSwap));

            self.emit(events::SwapCancelled { encodedSwap });
        }

        fn executeSwap(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            recipient: EthAddress,
            depositToPool: bool
        ) {
            let (poolIndex, initiator, fromAddress) = self.getPostedSwap(encodedSwap);
            assert(fromAddress.is_non_zero(), 'Swap does not exists');
            assert(poolIndex != 0, 'Pool index cannot be 0');

            MesonHelpers::_checkReleaseSignature(encodedSwap, recipient, r, yParityAndS, initiator);
            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, 0_felt252.try_into().unwrap()));

            let amount = MesonHelpers::_amountFrom(encodedSwap);
            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexFrom(tokenIndex, poolIndex);
            if depositToPool {
                self.storage.balanceOfPoolToken.write(
                    poolTokenIndex,
                    self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
                );
            } else {
                let poolOwner = self.storage.ownerOfPool.read(poolIndex);
                self.storage._withdrawToken(tokenIndex, poolOwner, amount);
            }

            self.emit(events::SwapExecuted { encodedSwap });
        }

        fn directExecuteSwap(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            initiator: EthAddress,
            recipient: EthAddress
        ) {
            self.verifyEncodedSwap(encodedSwap);

            MesonHelpers::_checkReleaseSignature(encodedSwap, recipient, r, yParityAndS, initiator);

            self.storage.postedSwaps.write(encodedSwap, (1, initiator, 0_felt252.try_into().unwrap()));

            let amount = MesonHelpers::_amountFrom(encodedSwap);
            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 1);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
            );

            self.storage._depositToken(tokenIndex, get_caller_address(), amount);
            self.emit(events::SwapExecuted { encodedSwap });
        }

        fn simpleExecuteSwap(ref self: ContractState, encodedSwap: u256) {
            self.verifyEncodedSwap(encodedSwap);

            self.storage.postedSwaps.write(encodedSwap, (1, 0.try_into().unwrap(), 0_felt252.try_into().unwrap()));

            let amount = MesonHelpers::_amountFrom(encodedSwap);
            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 1);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
            );

            self.storage._depositToken(tokenIndex, get_caller_address(), amount);
            self.emit(events::SwapExecuted { encodedSwap });
        }
    }

    #[abi(embed_v0)]
    impl MesonPools of MesonPoolsTrait<ContractState> {

        // Modifier
        fn forTargetChain(self: @ContractState, encodedSwap: u256) {
            assert(
                MesonHelpers::_versionFrom(encodedSwap) == MesonConstants::MESON_PROTOCOL_VERSION,
                'Incorrect encoding version'
            );

            assert(
                MesonHelpers::_outChainFrom(encodedSwap) == MesonConstants::SHORT_COIN_TYPE,
                'Swap not for this chain'
            );
        }

        // Write functions (LPs)
        fn depositAndRegister(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let poolOwner = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive');
            assert(poolIndex != 0, 'Cannot use 0 as pool index');
            assert(
                self.storage.ownerOfPool.read(poolIndex).is_zero(),
                'Pool index already registered'
            );
            assert(
                self.storage.poolOfAuthorizedAddr.read(poolOwner) == 0,
                'Caller addr already registered'
            );

            self.storage.ownerOfPool.write(poolIndex, poolOwner);
            self.storage.poolOfAuthorizedAddr.write(poolOwner, poolIndex);

            self.storage._depositToken(tokenIndex, poolOwner, amount);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
            );

            self.emit(events::PoolRegistered { poolIndex, owner: poolOwner });
            self.emit(events::PoolDeposited { poolTokenIndex, amount });
        }

        fn deposit(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let callerAddress = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive');
            assert(poolIndex != 0, 'Cannot use 0 as pool index');
            assert(
                self.storage.poolOfAuthorizedAddr.read(callerAddress) == poolIndex,
                'Only for authorized addr'
            );

            self.storage._depositToken(tokenIndex, callerAddress, amount);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
            );

            self.emit(events::PoolDeposited { poolTokenIndex, amount });
        }

        fn withdraw(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let poolOwner = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive');
            assert(poolIndex != 0, 'Cannot use 0 as pool index');
            assert(
                self.storage.ownerOfPool.read(poolIndex) == poolOwner,
                'Only for pool owner'
            );

            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) - amount
            );
            self.storage._withdrawToken(tokenIndex, poolOwner, amount);

            self.emit(events::PoolWithdrawn { poolTokenIndex, amount });
        }

        fn addAuthorizedAddr(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(poolIndex != 0, 'No registered pool');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Only for pool owner'
            );
            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == 0,
                'Addr authorized to another pool'
            );

            self.storage.poolOfAuthorizedAddr.write(addr, poolIndex);
            self.emit(events::PoolAuthorizedAddrAdded { poolIndex, addr });
        }

        fn removeAuthorizedAddr(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(poolIndex != 0, 'No registered pool');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Only for pool owner'
            );
            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == poolIndex,
                'Addr not authorized'
            );

            self.storage.poolOfAuthorizedAddr.write(addr, 0);
            self.emit(events::PoolAuthorizedAddrRemoved { poolIndex, addr });
        }

        fn transferPoolOwner(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(poolIndex != 0, 'No registered pool');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Only for pool owner'
            );
            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == poolIndex,
                'Addr not authorized'
            );

            self.storage.ownerOfPool.write(poolIndex, addr);
            self.emit(events::PoolOwnerTransferred { poolIndex, prevOwner: poolOwner, newOwner: addr });
        }

        // Write functions (users)
        fn lockSwap(
            ref self: ContractState,
            encodedSwap: u256,
            initiator: EthAddress,
            recipient: ContractAddress
        ) {
            self.forTargetChain(encodedSwap);
            assert(recipient.is_non_zero(), 'Recipient cannot be zero');

            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (_poolIndex, _until, _) = self.getLockedSwap(swapId);
            assert(_poolIndex == 0, 'Swap already exists');

            let poolIndex = self.storage.poolOfAuthorizedAddr.read(get_caller_address());
            assert(poolIndex != 0, 'No registered pool');

            let until = get_block_timestamp().into() + MesonConstants::LOCK_TIME_PERIOD;
            assert(
                until < MesonHelpers::_expireTsFrom(encodedSwap) - 5 * 60,
                'Expire time is soon'
            );

            let poolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, poolIndex);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) - MesonHelpers::_amountToLock(encodedSwap)
            );

            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            if coreAmount > 0 {
                assert(false, 'Swap for core not implemented');
            }

            self.storage.lockedSwaps.write(swapId, (poolIndex, until.try_into().unwrap(), recipient));

            self.emit(events::SwapLocked { encodedSwap });
        }

        fn unlock(ref self: ContractState, encodedSwap: u256, initiator: EthAddress) {
            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (poolIndex, until, _) = self.getLockedSwap(swapId);
            assert(until != 0, 'Swap does not exist');
            assert(until < get_block_timestamp().into(), 'Swap still in lock');

            let poolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, poolIndex);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) + MesonHelpers::_amountToLock(encodedSwap)
            );

            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            if coreAmount > 0 {
                assert(false, 'Swap for core not implemented');
            }

            self.storage.lockedSwaps.write(swapId, (0, 0, 0_felt252.try_into().unwrap()));

            self.emit(events::SwapUnlocked { encodedSwap });
        }

        fn release(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            initiator: EthAddress
        ) {
            assert(
                MesonHelpers::_expireTsFrom(encodedSwap) > get_block_timestamp().into(),
                'Cannot release because expired'
            );

            let feeWaived = MesonHelpers::_feeWaived(encodedSwap);
            if feeWaived {
                self.onlyPremiumManager();
            }

            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (poolIndex, until, recipient) = self.getLockedSwap(swapId);
            assert(until != 0, 'Swap does not exist');

            let recipientAsEth = MesonHelpers::_ethAddressFromStarknet(recipient);
            MesonHelpers::_checkReleaseSignature(encodedSwap, recipientAsEth, r, yParityAndS, initiator);
            self.storage.lockedSwaps.write(swapId, (poolIndex, 0, recipient));

            let mut releaseAmount = MesonHelpers::_amountToLock(encodedSwap);
            if (!feeWaived) {
                let serviceFee = MesonHelpers::_serviceFee(encodedSwap);
                releaseAmount -= serviceFee;
                let serviceFeePoolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, 0);
                self.storage.balanceOfPoolToken.write(
                    serviceFeePoolTokenIndex,
                    self.storage.balanceOfPoolToken.read(serviceFeePoolTokenIndex) + serviceFee
                );
            }

            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            if coreAmount > 0 {
                assert(false, 'Swap for core not implemented');
            }

            self.storage._withdrawToken(
                MesonHelpers::_outTokenIndexFrom(encodedSwap), recipient, releaseAmount
            );

            self.emit(events::SwapReleased { encodedSwap });
        }

        fn directRelease(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            initiator: EthAddress,
            recipient: ContractAddress
        ) {
            self.forTargetChain(encodedSwap);
            assert(recipient.is_non_zero(), 'Recipient cannot be zero');

            let feeWaived = MesonHelpers::_feeWaived(encodedSwap);
            if feeWaived {
                self.onlyPremiumManager();
            }

            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (_poolIndex, _until, _) = self.getLockedSwap(swapId);
            assert(_poolIndex == 0, 'Swap already exists');

            let poolIndex = self.storage.poolOfAuthorizedAddr.read(get_caller_address());
            assert(poolIndex != 0, 'No registered pool');

            if r != 0 {
                assert(
                    MesonHelpers::_expireTsFrom(encodedSwap) > get_block_timestamp().into(),
                    'Cannot release because expired'
                );
                let recipientAsEth = MesonHelpers::_ethAddressFromStarknet(recipient);
                MesonHelpers::_checkReleaseSignature(encodedSwap, recipientAsEth, r, yParityAndS, initiator);
            } else {
                self.onlyPremiumManager();
            }
            self.storage.lockedSwaps.write(swapId, (1, 0, recipient));

            let mut releaseAmount = MesonHelpers::_amountToLock(encodedSwap);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, poolIndex);
            self.storage.balanceOfPoolToken.write(
                poolTokenIndex,
                self.storage.balanceOfPoolToken.read(poolTokenIndex) - releaseAmount
            );

            if (!feeWaived) {
                let serviceFee = MesonHelpers::_serviceFee(encodedSwap);
                releaseAmount -= serviceFee;
                let serviceFeePoolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, 0);
                self.storage.balanceOfPoolToken.write(
                    serviceFeePoolTokenIndex,
                    self.storage.balanceOfPoolToken.read(serviceFeePoolTokenIndex) + serviceFee
                );
            }

            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            if coreAmount > 0 {
                assert(false, 'Swap for core not implemented');
            }

            self.storage._withdrawToken(
                MesonHelpers::_outTokenIndexFrom(encodedSwap), recipient, releaseAmount
            );

            self.emit(events::SwapReleased { encodedSwap });
        }
    }
}
