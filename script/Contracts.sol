// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

/// @title MainnetKeeperContracts
/// @notice Mainnet contract addresses for StrategyKeeper deployment
library MainnetKeeperContracts {
    // ═══════════════════════════════════════════════════════════════════════════
    // TOKENS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice USDC stablecoin
    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // ═══════════════════════════════════════════════════════════════════════════
    // YIELDNEST CONTRACTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice ynRWAx vault
    address public constant YNRWAX = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8;

    /// @notice FlexStrategy for ynRWAx
    address public constant FLEX_STRATEGY = 0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B;

    /// @notice Fee wallet for keeper fee collection
    address public constant FEE_WALLET = 0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183;

    /// @notice Rewards sweeper - receives Sablier streams for yield distribution
    address public constant REWARDS_SWEEPER = 0xbAC19FD66262629eEA13F1fd36ba9ae654bDfc76;

    /// @notice Borrower address - receives principal from keeper disbursements
    address public constant BORROWER = 0xaa7f79Bb105833D655D1C13C175142c44e209912;

    // ═══════════════════════════════════════════════════════════════════════════
    // EXTERNAL PROTOCOLS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Sablier LockupLinear contract for streaming payments
    address public constant SABLIER_LOCKUP_LINEAR = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;

    // ═══════════════════════════════════════════════════════════════════════════
    // GNOSIS SAFE INFRASTRUCTURE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Safe singleton (v1.4.1)
    address public constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;

    /// @notice Safe proxy factory
    address public constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
}
