# Flow Deployment Checklist

Assumptions:
- stream `11` already exists
- stream `11` is already active
- `FlowValidator`, `FlowHandler`, and `FlowStrategyKeeper` are already deployed

Deployed addresses:
- Strategy Safe: `0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- Yn Security Council: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- Yn Processor: `0x7e92AbC00F58Eb325C7fC95Ed52ACdf74584Be2c`
- Flow SafeGuard: `0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- FlowValidator: `0x0E013f48d8B0969c749a325E3f1ac3119641167E`
- FlowHandler proxy: `0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`
- FlowHandler implementation: `0x7195D3fD9Cb2Ac50cD31AA3d56Ef5A43bED086A1`
- FlowStrategyKeeper: `0x04C00d974cdFA60F16C9615B8C45A85EC680ef76`

## 1. Enable the module

Submit a Safe transaction from the Strategy Safe itself:

- signing Safe: `0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- `to = 0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- `function = enableModule(address module)`
- `module = 0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`

## 2. Grant the handler role

Submit from the Yn Security Council:

- signing Safe: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- `to = 0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`
- `function = grantRole(bytes32,address)`

- `DISBURSE_OPERATOR_ROLE -> 0x04C00d974cdFA60F16C9615B8C45A85EC680ef76`

## 3. Generate SafeGuard rule calldata

```bash
FLOW_VALIDATOR=0x0E013f48d8B0969c749a325E3f1ac3119641167E forge script script/deployment/flow/ConfigureFlowSafeGuard.s.sol:ConfigureFlowSafeGuard --rpc-url https://eth-mainnet.g.alchemy.com/v2/1FX7IZKqADVmU4ew3b7WD6NYNK5Ui0N7
```

This prints:
- SafeGuard target: `0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- calldata for `setProcessorRules(...)`

## 4. Submit the SafeGuard config

Manually submit the printed calldata:

- signing Safe: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- `to = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
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
