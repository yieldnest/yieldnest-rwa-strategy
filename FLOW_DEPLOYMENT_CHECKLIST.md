# Flow Deployment Checklist

Assumptions:
- stream `11` already exists
- stream `11` is already active
- `FlowValidator`, `FlowHandler`, and `FlowStrategyKeeper` are already deployed

## Repo setup

Clone the repo and check out this branch before running the scripts:

```bash
git clone <repo-url>
cd yieldnest-rwa-strategy
git checkout feature/sablier-flow-stream
```

Deployed addresses:
- Strategy Safe: `0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- Yn Security Council: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- Yn Processor: `0x7e92AbC00F58Eb325C7fC95Ed52ACdf74584Be2c`
- Flow SafeGuard: `0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- FlowValidator: `0x0E013f48d8B0969c749a325E3f1ac3119641167E`
- FlowHandler proxy: `0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`
- FlowHandler implementation: `0x7195D3fD9Cb2Ac50cD31AA3d56Ef5A43bED086A1`
- FlowStrategyKeeper: `0x04C00d974cdFA60F16C9615B8C45A85EC680ef76`

Run setup verification with:
```bash
FLOW_DEPLOYED=true forge script script/deployment/flow/VerifyFlowSetup.s.sol:VerifyFlowSetup --rpc-url $RPC_URL
```

Run bytecode verification with:
```bash
bash script/deployment/flow/verify-bytecode.sh $RPC_URL
```

## 1. Enable the module

Submit a Safe transaction from the Strategy Safe itself:

- signing Safe: `0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- `to = 0xb34E69c23Df216334496DFFd455618249E6bbFa9`
- `function = enableModule(address module)`
- `module = 0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`


https://app.safe.global/transactions/tx?safe=eth:0xb34E69c23Df216334496DFFd455618249E6bbFa9&id=multisig_0xb34E69c23Df216334496DFFd455618249E6bbFa9_0xc041a51e4b3b8f9893f1f167f8cf8999d18e8bf4d4be27bb8c4fb3f88f7e84af

## 2. Grant the handler role

Submit from the Yn Security Council:

- signing Safe: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- `to = 0x8302d2924e3F2d519cA75b9a95fDa0395AEbd2f8`
- `function = grantRole(bytes32,address)`

- `DISBURSE_OPERATOR_ROLE -> 0x04C00d974cdFA60F16C9615B8C45A85EC680ef76`

## 3. Generate SafeGuard rule calldata

```bash
FLOW_VALIDATOR=0x0E013f48d8B0969c749a325E3f1ac3119641167E forge script script/deployment/flow/ConfigureFlowSafeGuard.s.sol:ConfigureFlowSafeGuard --rpc-url $RPC_URL
```

This prints:
- SafeGuard target: `0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- calldata for `setProcessorRules(...)`

## 4. Submit the SafeGuard config

Manually submit the printed calldata:

- signing Safe: `0xfcad670592a3b24869C0b51a6c6FDED4F95D6975`
- `to = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e`
- `data = printed calldata`


TX for steps 2, 3, 4:


https://app.safe.global/transactions/tx?safe=eth:0xfcad670592a3b24869C0b51a6c6FDED4F95D6975&id=multisig_0xfcad670592a3b24869C0b51a6c6FDED4F95D6975_0xd54b9e13ef37b5e7cb037e2a4204a5e75419cef40c857d07fb2fa30d35409537



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
