## RWA Flex Strategy



### Flex Strategy verification

#### Verify FlexStrategyDeployer

The strategy is deployed by `FlexStrategyDeployer.sol` in one transaction.

One needs to only verify the bytecode of the FlexStrategyDeployer (the `deployer` field in the JSON deployment file) and all its constrcutor parameters + implementations.


Run 


```forge test --rpc-url YOUR_PRC```


See all tests pass and get the build created.

Do the following to verify:

For the *example* deployer at `0x4558E566F245CE69B6EC2f12c5b8638ce8c6b829` go to:

https://etherscan.io/address/0x4558E566F245CE69B6EC2f12c5b8638ce8c6b829#code

Take the `Contract Creation Code` at the bottom, and the bytecode in `out/FlexStrategyDeployer.sol/FlexStrategyDeployer.json` 

And ensure both match for the length of the build bytecode (the latter). The `Contract Creation Code` ends with the constructor parameters.


#### Verify Implementations


Run the following to verify the bytecode for the implementation contracts:

```
 bash script/verification/verify-bytecode.sh $DEPLOYMENT_FILE_PATH $ETHERSCAN_API_KEY $RPC_URL
```

Caveat: this currently does *not* work for FlexStrategy.sol due to the External Lib dependencies.
Verify that one manually.


Example:

```
bash script/verification/verify-bytecode.sh "deployments/ynFlex-USDC-ynRWAx-SPV1-1.json" XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX "https://eth-mainnet.g.alchemy.com/v2/ALCHEMY_API_KEY"
```

