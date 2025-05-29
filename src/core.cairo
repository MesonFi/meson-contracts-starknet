#[starknet::contract]
mod Meson {
    use starknet::{
        EthAddress, ContractAddress, contract_address::ContractAddressZeroable,
        eth_address::EthAddressZeroable, get_caller_address, get_block_timestamp,
        get_contract_address,
    };
    use meson_starknet::interface::{
        MesonViewStorageTrait, MesonManagerTrait, MesonSwapTrait, MesonPoolsTrait
    };
    use meson_starknet::utils::MesonConstants;
    use meson_starknet::utils::MesonHelpers;
    use meson_starknet::utils::MesonStates::MesonStatesComponent;

    component!(path: MesonStatesComponent, storage: storage, event: MesonEvent);

    impl MesonInternalImpl = MesonStatesComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[nested(v0)]
        #[substorage(v0)]
        storage: MesonStatesComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        MesonEvent: MesonStatesComponent::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.storage.owner.write(owner);
        self.storage.premiumManager.write(owner);
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

        fn indexOfToken(self: @ContractState, token: ContractAddress) -> u8 {
            self.storage.indexOfToken.read(token)
        }

        fn tokenForIndex(self: @ContractState, index: u8) -> ContractAddress {
            self.storage.tokenForIndex.read(index)
        }

        fn ownerOfPool(self: @ContractState, poolIndex: u64) -> ContractAddress {
            self.storage.ownerOfPool.read(poolIndex)
        }

        fn poolOfAuthorizedAddr(self: @ContractState, addr: ContractAddress) -> u64 {
            self.storage.poolOfAuthorizedAddr.read(addr)
        }

        fn poolTokenBalance(
            self: @ContractState, token: ContractAddress, addr: ContractAddress
        ) -> u256 {
            let tokenIndex = self.storage.indexOfToken.read(token);
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(addr);
            if (poolIndex == 0 || tokenIndex == 0) {
                0
            } else {
                let poolTokenIndex = MesonHelpers::_poolTokenIndexFrom(tokenIndex, poolIndex);
                self.storage.balanceOfPoolToken.read(poolTokenIndex)
            }
        }

        fn serviceFeeCollected(self: @ContractState, tokenIndex: u8) -> u256 {
            let poolTokenIndex: u64 = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 0);
            self.storage.balanceOfPoolToken.read(poolTokenIndex)
        }

        fn getPostedSwap(
            self: @ContractState, encodedSwap: u256
        ) -> (u64, EthAddress, ContractAddress) {
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
                if token != ContractAddressZeroable::zero() {
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
            assert(get_caller_address() == self.storage.owner.read(), 'Only owner can call!');
        }

        fn onlyPremiumManager(self: @ContractState) {
            assert(
                get_caller_address() == self.storage.premiumManager.read(),
                'Only premium manager can call!'
            );
        }

        // Write functions
        fn addSupportToken(ref self: ContractState, token: ContractAddress, index: u8) {
            self.onlyOwner();
            self.storage._addSupportToken(token, index);
        }

        fn removeSupportToken(ref self: ContractState, index: u8) {
            self.onlyOwner();
            self.storage._removeSupportToken(index);
        }

        fn transferOwnership(ref self: ContractState, newOwner: ContractAddress) {
            self.onlyOwner();
            self.storage._transferOwnership(newOwner);
        }

        fn transferPremiumManager(ref self: ContractState, newPremiumManager: ContractAddress) {
            self.onlyPremiumManager();
            self.storage._transferPremiumManager(newPremiumManager);
        }

        fn withdrawServiceFee(
            ref self: ContractState, tokenIndex: u8, amount: u256, toPoolIndex: u64
        ) {
            self.onlyOwner();
            assert(
                self.storage.ownerOfPool.read(toPoolIndex) != ContractAddressZeroable::zero(),
                'Pool index not registered'
            );
            let poolFrom = MesonHelpers::_poolTokenIndexFrom(tokenIndex, 0);
            let poolTo = MesonHelpers::_poolTokenIndexFrom(tokenIndex, toPoolIndex);
            self
                .storage
                .balanceOfPoolToken
                .write(poolFrom, self.storage.balanceOfPoolToken.read(poolFrom) - amount);
            self
                .storage
                .balanceOfPoolToken
                .write(poolTo, self.storage.balanceOfPoolToken.read(poolTo) + amount);
        }
    }

    #[abi(embed_v0)]
    impl MesonSwap of MesonSwapTrait<ContractState> {
        // Modifier
        fn verifyEncodedSwap(self: @ContractState, encodedSwap: u256) {
            assert(
                MesonHelpers::_inChainFrom(encodedSwap) == MesonConstants::SHORT_COIN_TYPE,
                'Swap not for this chain!'
            );
            assert(
                MesonHelpers::_tokenType(
                    MesonHelpers::_inTokenIndexFrom(encodedSwap)
                ) == MesonHelpers::_tokenType(MesonHelpers::_outTokenIndexFrom(encodedSwap)),
                'In & out token types not match!'
            );

            let (poolIndex, initiator, fromAddress) = self.getPostedSwap(encodedSwap);
            assert(
                poolIndex == 0
                    && initiator == EthAddressZeroable::zero()
                    && fromAddress == ContractAddressZeroable::zero(),
                'Swap already exists'
            );

            assert(
                MesonHelpers::_amountFrom(encodedSwap) <= MesonConstants::MAX_SWAP_AMOUNT,
                'Swap amount too large!'
            );

            let delta = MesonHelpers::_expireTsFrom(encodedSwap) - get_block_timestamp().into();
        // assert(delta > MesonConstants::MIN_BOND_TIME_PERIOD, 'Expire ts too early');
        // assert(delta < MesonConstants::MAX_BOND_TIME_PERIOD, 'Expire ts too late');
        // TODO: add it back when it's not deployed on the local devnet
        }

        // Write functions
        fn postSwap(ref self: ContractState, encodedSwap: u256, postingValue: u256) {
            self.verifyEncodedSwap(encodedSwap);

            let initiator = MesonHelpers::_initiatorFromPosted(postingValue);
            let poolIndex = MesonHelpers::_poolIndexFromPosted(postingValue);

            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let fromAddress = get_caller_address();

            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, fromAddress));
            self
                .storage
                ._depositToken(tokenIndex, fromAddress, MesonHelpers::_amountFrom(encodedSwap));
        }

        fn postSwapFromInitiator(ref self: ContractState, encodedSwap: u256, postingValue: u256) {
            self.verifyEncodedSwap(encodedSwap);

            let initiator = MesonHelpers::_initiatorFromPosted(postingValue);
            let poolIndex = MesonHelpers::_poolIndexFromPosted(postingValue);

            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let fromAddress = get_caller_address();

            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, fromAddress));
            self
                .storage
                ._depositToken(tokenIndex, fromAddress, MesonHelpers::_amountFrom(encodedSwap));
        }

        fn bondSwap(ref self: ContractState, encodedSwap: u256, poolIndex: u64) {
            let (prevPoolIndex, initiator, fromAddress) = self.getPostedSwap(encodedSwap);
            let poolOwner = get_caller_address();

            assert(fromAddress != ContractAddressZeroable::zero(), 'Swap not exists!');
            assert(prevPoolIndex == 0, 'Swap bonded to others!');
            assert(
                self.storage.poolOfAuthorizedAddr.read(poolOwner) == poolIndex,
                'Not authorized address!'
            );

            self.storage.postedSwaps.write(encodedSwap, (poolIndex, initiator, fromAddress));
        }

        fn cancelSwap(ref self: ContractState, encodedSwap: u256) {
            let (oldPoolIndex, initiator, fromAddress) = self.getPostedSwap(encodedSwap);
            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);

            assert(fromAddress != ContractAddressZeroable::zero(), 'Swap not exists!');
            assert(
                MesonHelpers::_expireTsFrom(encodedSwap) < get_block_timestamp().into(),
                'Swap is still locked!'
            );

            self
                .storage
                .postedSwaps
                .write(
                    encodedSwap, (0, EthAddressZeroable::zero(), ContractAddressZeroable::zero())
                );
            self
                .storage
                ._safeTransfer(tokenIndex, fromAddress, MesonHelpers::_amountFrom(encodedSwap));
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
            let amount = MesonHelpers::_amountFrom(encodedSwap);
            let tokenIndex = MesonHelpers::_inTokenIndexFrom(encodedSwap);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexFrom(tokenIndex, poolIndex);

            assert(poolIndex != 0, 'Pool index cannot be 0!');

            // TODO: add it back. 
            // _checkReleaseSignature(encodedSwap, recipient, r, yParityAndS, initiator);

            self
                .storage
                .postedSwaps
                .write(encodedSwap, (poolIndex, initiator, ContractAddressZeroable::zero()));
            if depositToPool {
                self
                    .storage
                    .balanceOfPoolToken
                    .write(
                        poolTokenIndex,
                        self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
                    );
            } else {
                let poolOwner = self.storage.ownerOfPool.read(poolIndex);
                self.storage._safeTransfer(tokenIndex, poolOwner, amount);
            }
        }
    }

    #[abi(embed_v0)]
    impl MesonPools of MesonPoolsTrait<ContractState> {
        // Modifier
        fn forTargetChain(self: @ContractState, encodedSwap: u256) {
            assert(
                MesonHelpers::_outChainFrom(encodedSwap) == MesonConstants::SHORT_COIN_TYPE,
                'Swap not for this chain!'
            );
        }

        // Write functions (LPs)
        fn depositAndRegister(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let poolOwner = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive!');
            assert(poolIndex != 0, 'Cannot use 0 as pool index!');
            assert(
                self.storage.ownerOfPool.read(poolIndex) == ContractAddressZeroable::zero(),
                'Pool index already registered!'
            );
            assert(
                self.storage.poolOfAuthorizedAddr.read(poolOwner) == 0, 'Signer already registered!'
            );

            self.storage.ownerOfPool.write(poolIndex, poolOwner);
            self.storage.poolOfAuthorizedAddr.write(poolOwner, poolIndex);

            self.storage._depositToken(tokenIndex, poolOwner, amount);
            self
                .storage
                .balanceOfPoolToken
                .write(
                    poolTokenIndex, self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
                );
        }

        fn deposit(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let authrizedAddress = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive!');
            assert(poolIndex != 0, 'Cannot use 0 as pool index!');
            assert(
                self.storage.poolOfAuthorizedAddr.read(authrizedAddress) == poolIndex,
                'Need an authorized address!'
            );

            self.storage._depositToken(tokenIndex, authrizedAddress, amount);
            self
                .storage
                .balanceOfPoolToken
                .write(
                    poolTokenIndex, self.storage.balanceOfPoolToken.read(poolTokenIndex) + amount
                );
        }

        fn withdraw(ref self: ContractState, amount: u256, poolTokenIndex: u64) {
            let poolOwner = get_caller_address();
            let poolIndex = MesonHelpers::_poolIndexFrom(poolTokenIndex);
            let tokenIndex = MesonHelpers::_tokenIndexFrom(poolTokenIndex);

            assert(amount > 0, 'Amount must be positive!');
            assert(poolIndex != 0, 'Cannot use 0 as pool index!');
            assert(self.storage.ownerOfPool.read(poolIndex) == poolOwner, 'Need the pool owner!');

            self
                .storage
                .balanceOfPoolToken
                .write(
                    poolTokenIndex, self.storage.balanceOfPoolToken.read(poolTokenIndex) - amount
                );
            self.storage._safeTransfer(tokenIndex, poolOwner, amount);
        }

        fn addAuthorizedAddr(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == 0, 'Authorized for another pool!'
            );
            assert(poolIndex != 0, 'Signer have not registered!');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Signer should be pool owner!'
            );

            self.storage.poolOfAuthorizedAddr.write(addr, poolIndex);
        }

        fn removeAuthorizedAddr(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == poolIndex,
                'Not an authorized address!'
            );
            assert(poolIndex != 0, 'Signer have not registered!');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Signer should be pool owner!'
            );

            self.storage.poolOfAuthorizedAddr.write(addr, 0);
        }

        fn transferPoolOwner(ref self: ContractState, addr: ContractAddress) {
            let poolOwner = get_caller_address();
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(poolOwner);

            assert(
                self.storage.poolOfAuthorizedAddr.read(addr) == poolIndex,
                'Not an authorized address!'
            );
            assert(poolIndex != 0, 'Signer have not registered!');
            assert(
                poolOwner == self.storage.ownerOfPool.read(poolIndex),
                'Signer should be pool owner!'
            );

            self.storage.ownerOfPool.write(poolIndex, addr);
        }

        // Write functions (users)
        fn lockSwap(
            ref self: ContractState,
            encodedSwap: u256,
            initiator: EthAddress,
            recipient: ContractAddress
        ) {
            self.forTargetChain(encodedSwap);

            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (existPoolIndex, _, _) = self.getLockedSwap(swapId);
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(get_caller_address());
            let poolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, poolIndex);
            let until = get_block_timestamp().into() + MesonConstants::LOCK_TIME_PERIOD;
            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);

            assert(existPoolIndex == 0, 'Swap already exists');
            assert(poolIndex != 0, 'Caller not registered!');
            assert(
                until < MesonHelpers::_expireTsFrom(encodedSwap) - 5 * 60, // 5 minutes left
                'Expire time is soon!'
            );

            if coreAmount > 0 { // TODO: add core token's case
            }
            self
                .storage
                .balanceOfPoolToken
                .write(
                    poolTokenIndex,
                    self.storage.balanceOfPoolToken.read(poolTokenIndex)
                        - MesonHelpers::_amountToLock(encodedSwap)
                );
            self
                .storage
                .lockedSwaps
                .write(swapId, (poolIndex, until.try_into().unwrap(), recipient));
        }

        fn unlock(ref self: ContractState, encodedSwap: u256, initiator: EthAddress) {
            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (poolIndex, until, recipient) = self.getLockedSwap(swapId);
            let poolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, poolIndex);
            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);

            assert(poolIndex != 0, 'Swap does not exist!');
            assert(until < get_block_timestamp().into(), 'Swap still in lock!');

            if coreAmount > 0 { // TODO
            }
            self
                .storage
                .balanceOfPoolToken
                .write(
                    poolTokenIndex,
                    self.storage.balanceOfPoolToken.read(poolTokenIndex)
                        + MesonHelpers::_amountToLock(encodedSwap)
                );
            self.storage.lockedSwaps.write(swapId, (0, 0, ContractAddressZeroable::zero()));
        }

        fn release(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            initiator: EthAddress
        ) {
            let feeWaived = MesonHelpers::_feeWaived(encodedSwap);
            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            let (poolIndex, until, recipient) = self.getLockedSwap(swapId);
            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            let recipientAsEth = MesonHelpers::_ethAddressFromStarknet(recipient);
            let serviceFeePoolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, 0);
            let mut releaseAmount = MesonHelpers::_amountToLock(encodedSwap);

            // TODO: add it back. 
            // _checkReleaseSignature(encodedSwap, recipientAsEth, r, yParityAndS, initiator);
            assert(poolIndex != 0, 'Swap does not exist!');
            assert(
                MesonHelpers::_expireTsFrom(encodedSwap) > get_block_timestamp().into(),
                'Cannot release. Expired!'
            );
            assert(recipient != ContractAddressZeroable::zero(), 'Recipient cannot be zero!');

            if feeWaived {
                self.onlyPremiumManager();
            } else {
                let serviceFee = MesonHelpers::_serviceFee(encodedSwap);
                releaseAmount -= serviceFee;
                self
                    .storage
                    .balanceOfPoolToken
                    .write(
                        serviceFeePoolTokenIndex,
                        self.storage.balanceOfPoolToken.read(serviceFeePoolTokenIndex) + serviceFee
                    );
            }
            if coreAmount > 0 { // TODO
            }
            self
                .storage
                ._safeTransfer(
                    MesonHelpers::_outTokenIndexFrom(encodedSwap), recipient, releaseAmount
                );
            self.storage.lockedSwaps.write(swapId, (poolIndex, 0, recipient));
        }

        fn directRelease(
            ref self: ContractState,
            encodedSwap: u256,
            r: u256,
            yParityAndS: u256,
            initiator: EthAddress,
            recipient: ContractAddress
        ) {
            let feeWaived = MesonHelpers::_feeWaived(encodedSwap);
            let swapId = MesonHelpers::_getSwapId(encodedSwap, initiator);
            // let (poolIndex, until, recipient) = self.getLockedSwap(swapId);
            let poolIndex = self.storage.poolOfAuthorizedAddr.read(get_caller_address());
            let (existPoolIndex, _, _) = self.getLockedSwap(swapId);
            // let tokenIndex = _outTokenIndexFrom(encodedSwap);
            let coreAmount = MesonHelpers::_coreTokenAmount(encodedSwap);
            let recipientAsEth = MesonHelpers::_ethAddressFromStarknet(recipient);
            let serviceFeePoolTokenIndex = MesonHelpers::_poolTokenIndexForOutToken(encodedSwap, 0);
            let mut releaseAmount = MesonHelpers::_amountToLock(encodedSwap);

            self.forTargetChain(encodedSwap);
            // MesonHelpers::_checkReleaseSignature(
            //     encodedSwap, recipientAsEth, r, yParityAndS, initiator
            // );
            // assert(poolIndex != 0, 'Swap does not exist!');
            assert(existPoolIndex == 0, 'Swap already exists');
            assert(poolIndex != 0, 'Caller not registered!');
            assert(
                MesonHelpers::_expireTsFrom(encodedSwap) > get_block_timestamp().into(),
                'Cannot release. Expired!'
            );
            assert(recipient != ContractAddressZeroable::zero(), 'Recipient cannot be zero!');

            if feeWaived {
                self.onlyPremiumManager();
            } else {
                let serviceFee = MesonHelpers::_serviceFee(encodedSwap);
                releaseAmount -= serviceFee;
                self
                    .storage
                    .balanceOfPoolToken
                    .write(
                        serviceFeePoolTokenIndex,
                        self.storage.balanceOfPoolToken.read(serviceFeePoolTokenIndex) + serviceFee
                    );
            }
            if coreAmount > 0 { // TODO
            }
            self
                .storage
                ._safeTransfer(
                    MesonHelpers::_outTokenIndexFrom(encodedSwap), recipient, releaseAmount
                );
            self.storage.lockedSwaps.write(swapId, (poolIndex, 0, recipient));
        }
    }
}
