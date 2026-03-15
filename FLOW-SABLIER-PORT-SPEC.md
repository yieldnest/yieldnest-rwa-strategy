
### Flow sablier port 


The docs for sablier flow are here:

https://docs.sablier.com/fides/flow/overview

The code is here:

https://github.com/sablier-labs/flow/tree/release

Some examples:

https://github.com/sablier-labs/evm-examples/tree/main/flow

Use the latest deployments for mainnet from here

https://docs.sablier.com/guides/flow/deployments




Add a secondary version of the contract called FlowStrategyKeeper.sol

this works the same but what it does is instead it  adjusts a sablier flow instance.

In that case it needs to adjust the rate based on the flow per second of earning 11% per year off of the sum being deposited.


Assume there are top up checkpoints every 28 days (the 28 days is a configurable parameter).


Therefore the yield withheld is not a fixed percentage of the sum being send to the borrower, is equal to what's needed up to the next checkpoint.

This system a stream is created before hand and already exists.

## The Flow Guard spec

Keep in mind the Flow guard should encapsulate the logic of knowing about a certain new loanAmount.

The loanAmount is used to derive the interestAmount for holdingPeriod and additionally calculate ratePerSecond delta.

Do not leave any of this logic in the FlowStrategyKeeper.

The FlowStrategyKeeper simply pases in the loanAmount it's aware of, but does not compute these things which are specific to the FlowGuard.


Let FlowStrategyKeeper get info abotu the interest paid by querying The FlowGuard.

Also make it so that the FlowGuard os only aware of the interest without fees. so in this case that's 11% for what the tests are using.

The FlowStrategyKeeper will need to be able to to deduce by querying the FlowGuard for interest, how much is the fee.

And that fee is added on top of the interest communicated by the FlowGuard.

So the fee is 1.1% that's 11% /10. the fraction is 10 for this new approach to work.

### Important: FlowStrategyKeeper must pass `available` (the full loanAmount) to FlowGuard

When calling `FlowGuard.increaseRate()`, the keeper must pass the original `available` amount — NOT the `principal` (which has interest and fee subtracted). The FlowGuard recomputes interest internally from the loanAmount. Passing `principal` instead would result in a completely different (smaller) interest calculation, breaking the expected yield holdback.

## Test - Just the Sablier Flow system on its own

Write a test that verifies sall this behaviour for a sablier FLOW stream on its own.


```
Rate $/s
  ^
  |         ┌──────────┐
  |         │          │         ┌──────┐
  |  ┌──────┤          │         │      │
  |  │      │          │         │      │
  |  │      │          └─────────┤      └────┐
  |  │      │                    │           │
  ──┴──────┴──────────┴─────────┴───────────┴──> time
     S0     S1        TOP-UP 0   S2   TOP-UP 1  (decrease)
```

### Core Operations

| Action | Sablier Flow Function | When |
|---|---|---|
| Start streaming | `flow.create()` | Vault onboarding / first yield period |
| Increase yield rate | `flow.adjustRatePerSecond(streamId, newRate)` | New strategy starts, higher APY |
| Decrease yield rate | `flow.adjustRatePerSecond(streamId, newRate)` | Strategy wind-down, lower APY |
| Top up balance | `flow.deposit(streamId, amount)` | Whenever vault has yield to distribute |

Test the situation of whewn the top up runs out.

Test the situation of being able to withdraw committed funds as well. 


Measure that this stream behaves as expected in that it keeps rmitting at the expect rate.



## Test  for FlowStrategyKeeper

Write a full integration test for the FlowStrategyKeeper. 

Verify interactions like topping up. 

Verify creation of new deposits of different sizes.

Verify what happens if top up doesn't ocme up in time.