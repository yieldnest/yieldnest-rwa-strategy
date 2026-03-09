
### Flow sablier port 


The docs for sablier flow are here:

https://docs.sablier.com/guides/flow/overview

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