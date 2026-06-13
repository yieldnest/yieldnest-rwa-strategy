# Flow Deployment Checklist

Assumptions:
- stream `11` already exists
- stream `11` is already active
- `FlowValidator`, `FlowHandler`, and `FlowStrategyKeeper` are already deployed

## 1. Enable the module

Submit a Safe transaction to the strategy Safe itself:

- `to = <strategy safe>`
- `function = enableModule(address module)`
- `module = <flowHandlerProxy>`

Get `flowHandlerProxy` from:
- `deployments/flow-handler-deployment.json` -> `.proxy`

## 2. Grant the handler role

On `FlowHandler`, grant:

- `DISBURSE_OPERATOR_ROLE -> <flowKeeper>`

Get `flowKeeper` from:
- `deployments/flow-keeper-deployment.json` -> `.keeper`

## 3. Generate SafeGuard rule calldata

```bash
FLOW_VALIDATOR=$(jq -r '.validator' deployments/flow-validator-deployment.json) forge script script/deployment/flow/ConfigureFlowSafeGuard.s.sol:ConfigureFlowSafeGuard --rpc-url https://eth-mainnet.g.alchemy.com/v2/1FX7IZKqADVmU4ew3b7WD6NYNK5Ui0N7
```

This prints:
- SafeGuard target
- calldata for `setProcessorRules(...)`

## 4. Submit the SafeGuard config

Manually submit the printed calldata:

- `to = printed SafeGuard address`
- `data = printed calldata`

## 5. Verify the final setup

```bash
FLOW_DEPLOYED=true forge script script/deployment/flow/VerifyFlowSetup.s.sol:VerifyFlowSetup --rpc-url https://eth-mainnet.g.alchemy.com/v2/1FX7IZKqADVmU4ew3b7WD6NYNK5Ui0N7
```

## 6. Verify deployed bytecode

```bash
bash script/deployment/flow/verify-bytecode.sh https://eth-mainnet.g.alchemy.com/v2/1FX7IZKqADVmU4ew3b7WD6NYNK5Ui0N7
```

## 7. Inspect live stream state

```bash
forge script script/commands/PrintFlowState.s.sol:PrintFlowState --rpc-url https://eth-mainnet.g.alchemy.com/v2/1FX7IZKqADVmU4ew3b7WD6NYNK5Ui0N7
```

Enter:
- `11`
