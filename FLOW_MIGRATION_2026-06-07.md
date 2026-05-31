# Flow Migration Runbook

This runbook covers the cutover from the current Sablier setup to the new `FlowHandler` + `FlowStrategyKeeper` system.

Target cutover time:

- `2026-06-07 15:00 UTC` (`3:00 PM GMT`)

Important operational note:

- Earlier notes in this repo reference `2026-06-07 16:00 UTC`.
- Before executing anything, resolve that discrepancy and treat one timestamp as canonical.
- This runbook assumes the canonical cutover time is `2026-06-07 15:00 UTC`.

## Scope

The target system is:

- `FlowValidator`
- `FlowHandler` behind a `TransparentUpgradeableProxy`
- `FlowStrategyKeeper`
- Safe module enablement on the strategy Safe
- SafeGuard processor rules for:
  - `USDC.approve`
  - `SablierFlow.deposit`
  - `SablierFlow.adjustRatePerSecond`
  - `USDC.transfer`

## Current Gaps In Repo Automation

This repo currently does **not** contain a dedicated production deployment script for:

- `FlowValidator`
- `FlowHandler` implementation + proxy
- `FlowStrategyKeeper`
- full Safe module enablement + SafeGuard rule installation for the Flow path

So the migration is operationally straightforward, but not yet one-click automated from this repo. The steps below are the required sequence.

## Target Addresses And Roles

Use the existing mainnet constants already referenced by the integration suite:

- `USDC`: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- `Sablier Flow`: `0x7a86d3e6894f9c5B5f25FFBDAaE658CFc7569623`
- `FlexStrategy`: `0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B`
- `Rewards Sweeper`: `0xbAC19FD66262629eEA13F1fd36ba9ae654bDfc76`
- `Borrower`: `0xaa7f79Bb105833D655D1C13C175142c44e209912`
- `Fee Wallet`: `0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183`
- `SafeGuard`: `0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- `Strategy Safe`: read from `FlexStrategy.accountingModule().safe()`

Recommended role shape:

- `FlowHandler.DEFAULT_ADMIN_ROLE`: governance / security council
- `FlowHandler.MANAGER_ROLE`: governance / security council
- `FlowHandler.DISBURSE_OPERATOR_ROLE`: `FlowStrategyKeeper`
- `FlowHandler.DECREASE_OPERATOR_ROLE`: ops or governance key used for downward adjustments
- `FlowStrategyKeeper.DEFAULT_ADMIN_ROLE`: governance / security council
- `FlowStrategyKeeper.CONFIG_MANAGER_ROLE`: governance / security council
- `FlowStrategyKeeper.PAUSER_ROLE`: governance / security council and emergency operator
- `FlowStrategyKeeper.KEEPER_ROLE`: automation key if using computed path
- `FlowStrategyKeeper.POWER_KEEPER_ROLE`: automation key if using manual path

## Parameters To Fix Before Deployment

These values need to be explicitly decided before deployment:

- `APR`
- `HOLDING_PERIOD`
- `MAX_APR` for `FlowValidator`
- `minThreshold`
- `minResidual`
- `minProcessingPercent`
- initial Flow prefund amount
- canonical cutover timestamp

From the current tests, the default operational values are:

- `APR = 0.11e18` (`11%`)
- `MAX_APR = 0.115e18` (`11.5%`)
- `HOLDING_PERIOD = 28 days`
- `minThreshold = 200_000e6`
- `minResidual = 1_000e6`
- `minProcessingPercent = 0.01e18` (`1%`)
- `feeFraction = 10`

## Starting Flow Rate

If the new Flow stream is intended to replace the full current aggregate payout stream at cutover, then based on the prior stream-set analysis the aggregate outgoing rate is:

- `2773.889368 USDC / day`

Equivalent forms:

- `0.032105201018518518 USDC / second`
- `32105.201018518518` USDC base units / second
- `UD21x18 raw = 32105201018518518`

For `restart(streamId, ratePerSecond)`, the rate parameter should therefore be:

```solidity
UD21x18.wrap(32105201018518518)
```

This equals:

- `32105.201018518518` base units / second
- `0.032105201018518518 USDC / second`

If the intended replacement rate is **not** the full current aggregate payout, recompute this before cutover. Do not reuse the number above blindly.

## Prefund Amounts

At the target rate above:

- `1 day` runway: `2,773.889368 USDC`
- `7 day` runway: `19,417.225576 USDC`
- `28 day` runway: `77,668.902304 USDC`
- `30 day` runway: `83,216.681040 USDC`

Recommended minimum:

- prefund at least `7 days`

Recommended operationally safer amount:

- prefund `28` to `30 days`

## Deployment Sequence

### 1. Create Or Identify The Flow Stream

Before cutover, create the target Sablier Flow stream with:

- `sender = strategy Safe`
- `recipient = rewards sweeper`
- `token = USDC`
- `transferable = true` only if that is still intended

Preferred pattern:

- create the stream **before** cutover at `rate = 0`
- record the resulting `streamId`

Why:

- `FlowHandler.disburse()` is intentionally only for active non-zero-rate streams
- the initial start of a zero-rate stream is an explicit `restart(...)` operation

### 2. Deploy `FlowValidator`

Deploy one `FlowValidator` with:

- `flow = Sablier Flow`
- `vault = FlexStrategy`
- `tokenDecimals = 6`
- one initial stream limit:
  - `streamId = <new stream id>`
  - `maxApr = 0.115e18` unless governance chooses another limit
- `admin = security council / governance`

### 3. Deploy `FlowHandler` Implementation

Deploy the `FlowHandler` implementation contract.

### 4. Deploy `FlowHandler` Proxy

Deploy a `TransparentUpgradeableProxy` pointing to the implementation, with `initialize(...)` parameters:

- `admin = temporary deployer if you need to finish setup first, otherwise governance`
- `safe = strategy Safe`
- `safeGuard = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- `flow = Sablier Flow`
- `streamId = <new stream id>`
- `token = USDC`
- `streamRecipient = rewards sweeper`
- `apr = chosen APR`
- `holdingPeriod = chosen holding period`
- `maxRateDelta = 0` unless you want an extra per-call clamp
- `maxRate = 0` unless you want an extra absolute local clamp
- `borrower = configured borrower`
- `feeWallet = configured fee wallet`
- `feeFraction = configured fee fraction`

Important:

- `FlowHandler.initialize()` does not currently verify that `safe`, `token`, and `streamRecipient` actually match the underlying Flow stream.
- Verify those fields manually before activation.

### 5. Enable `FlowHandler` As A Safe Module

On the strategy Safe, execute:

- `enableModule(flowHandlerProxy)`

### 6. Configure SafeGuard Rules

Install processor rules on the deployed SafeGuard for the exact path `FlowHandler` needs:

- `USDC.approve(SablierFlow, amount)`
- `SablierFlow.deposit(streamId, amount, safe, recipient)`
- `SablierFlow.adjustRatePerSecond(streamId, rate)` with `FlowValidator`
- `USDC.transfer(borrower, amount)`
- `USDC.transfer(feeWallet, amount)`

This is the same rule shape used in `test/integration/flow-keeper.spec.sol`.

### 7. Deploy `FlowStrategyKeeper`

Deploy `FlowStrategyKeeper` with constructor roles:

- `_admin = governance`
- `_initializer = setup operator`
- `_pauser = governance or designated emergency pauser`
- `_processor = automation key`

Then call `initialize(...)` with:

- `vault = FlexStrategy`
- `targetStrategy = FlexStrategy`
- `safe = strategy Safe`
- `baseAsset = USDC`
- `flowHandler = FlowHandler proxy`
- `minThreshold = chosen threshold`
- `minResidual = chosen residual`
- `minProcessingPercent = chosen fallback percentage`

### 8. Grant Roles

Grant:

- `FlowHandler.DISBURSE_OPERATOR_ROLE -> FlowStrategyKeeper`
- `FlowHandler.DECREASE_OPERATOR_ROLE -> designated downward-adjustment operator`
- `FlowHandler.DEFAULT_ADMIN_ROLE -> governance`
- `FlowHandler.MANAGER_ROLE -> governance`
- `FlowStrategyKeeper.CONFIG_MANAGER_ROLE -> governance`
- `FlowStrategyKeeper.PAUSER_ROLE -> governance / emergency operator`
- `FlowStrategyKeeper.KEEPER_ROLE -> automation`
- `FlowStrategyKeeper.POWER_KEEPER_ROLE -> automation`

Then revoke / renounce temporary deployer roles.

## Pre-Cutover Checklist

Complete these before `2026-06-07 15:00 UTC`:

1. Stream exists and `streamId` is recorded.
2. `FlowValidator` is deployed and configured for that `streamId`.
3. `FlowHandler` proxy is deployed and points at the correct stream.
4. `FlowHandler` is enabled as a Safe module.
5. SafeGuard processor rules are installed.
6. `FlowStrategyKeeper` is deployed and initialized.
7. Keeper has `DISBURSE_OPERATOR_ROLE`.
8. Governance holds the intended admin roles.
9. The new Flow stream is prefunded.
10. A direct Safe `restart(streamId, rate)` transaction is prepared and signed.

## How To Prefund The New Flow

Because `FlowHandler.disburse()` cannot start a zero-rate stream, prefunding should be done directly through the Safe before cutover.

Direct Safe actions:

1. `USDC.approve(SablierFlow, prefundAmount)`
2. `SablierFlow.deposit(streamId, prefundAmount, safe, rewardsSweeper)`

Recommended prefund target:

- `77,668.902304 USDC` for `28 days` of runway at the replacement rate

## Cutover Procedure At 2026-06-07 15:00 UTC

At the canonical cutover timestamp:

1. Confirm the legacy system should stop emitting at that timestamp.
2. Confirm the new Flow stream has the expected prefunded balance.
3. Execute directly from the Safe:

```solidity
restart(streamId, UD21x18.wrap(32105201018518518))
```

4. Confirm onchain:
   - `getRatePerSecond(streamId)` equals `32105201018518518`
   - `getRecipient(streamId)` is the rewards sweeper
   - `getSender(streamId)` is the strategy Safe

If your intended cutover rate differs from the aggregate replacement rate above, change the `restart(...)` parameter accordingly.

## Post-Cutover Activation

Once the stream is live:

1. Keep `FlowHandler` active as the Safe module.
2. Keep `FlowStrategyKeeper` live with the automation roles.
3. Use `keeper.processInflows(...)` only after the stream is active and non-zero.

Operational rule:

- do **not** expect `FlowHandler.disburse()` to start a paused stream
- starting a paused stream remains a direct `restart(...)` operation

## Immediate Post-Cutover Verification

Check:

1. `FlowHandler.safe()` matches the strategy Safe.
2. `FlowHandler.flow()` matches Sablier Flow.
3. `FlowHandler.streamId()` matches the created stream.
4. `FlowHandler.streamRecipient()` matches the current stream NFT owner / recipient.
5. `FlowHandler.safeGuard()` is the deployed SafeGuard.
6. `FlowValidator.getMaxApr(streamId)` matches governance intent.
7. `Safe.isModuleEnabled(flowHandler)` is true.
8. `safeguard.getProcessorRule(...adjustRatePerSecond...)` points to `FlowValidator`.
9. `keeper.getConfig().flowHandler` points to the deployed FlowHandler proxy.

## First Keeper Run

After cutover and after new inflows arrive:

1. Check Safe balance.
2. Check `minResidual`.
3. Decide whether to use:
   - `processInflows()` for computed operation
   - or `processInflows(vaultAllocation, available)` for manual operation

The first keeper run should be small and supervised.

## Known Risks To Keep In Mind

### Keeper / handler config is not cross-checked

`FlowStrategyKeeper` does not currently verify that its configured:

- `safe`
- `baseAsset`
- `flowHandler`

are internally consistent with the target `FlowHandler`.

That means setup must manually ensure:

- `keeper.safe == flowHandler.safe()`
- `keeper.baseAsset == flowHandler.token()`

### `FlowHandler.initialize()` does not bind stream identity strongly enough

The contract currently does not verify at initialization that:

- the Flow stream sender is the configured Safe
- the Flow stream token is the configured token
- the Flow stream recipient matches the configured recipient

This must be verified manually at deployment time.

### Time mismatch risk

Do not execute with unresolved ambiguity between:

- `2026-06-07 15:00 UTC`
- `2026-06-07 16:00 UTC`

One canonical cutover timestamp must be declared before execution.

## Recommended Dry Run

Before mainnet cutover:

1. fork mainnet
2. create the target Flow stream
3. deploy validator / handler / keeper
4. enable module
5. install SafeGuard rules
6. prefund the stream
7. execute `restart(...)`
8. run one `keeper.processInflows(...)`
9. verify borrower, fee, and stream-rate effects

Without that dry run, this migration is still too manual.
