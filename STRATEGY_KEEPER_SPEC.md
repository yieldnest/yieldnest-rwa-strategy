
# Strategy Keeper

Write a system that does the following

Has a permisionless keeper function with on parameters.

This function checks if a minimum amount of baseAsset resides in a Vault.
If amount exceeds treshold, then use the IVault processor function to allocate
the amount to a targetStrategy with an approve/deposit call.

This strategy is a Flex strategy so it has an accountingModule that references a SAFE.

the funds now should reside in this SAFE.

at this point, take all the baseAsset funds that exceed minResidual amount in the SAFE.



Using this USDC do the following:



Calculate like in this example, given that Amount (The amount here is just an example):

Amount: 34,500 USDC
APR: 12.1%

Holding 28 days yield in advance

34500 * 12.1 / 100 * 28 / 365
320.23561643835615

Interest: $320.24
Final amount:
34500 - 320.24
34179.76

Make the calculation more precise, use 1e18 for 100%.

DO THE FOLLOWING AS THOUGH YOU ARE A SIGNER ON THE GNOSIS SAFE.

Assume the safe is 2/X. so 2 signatures are needed. The keepers address is a signer.

In addition it has another companion contract that can proxy stuff and is also a signer.

so it can push 2 signatures and execute.

Make sure this follows exactly the Gnosis safe interface and signs these as a smart contract.

Make sure it executes

Transfer the final amount to a borrowerAdress that is a config option.



Taking that interest amount, that and know that 1 / 11 of this should be sent to a fee wallet.

With the rest of the 10/11 create a sablier stream that starts now and ends in 28 days, and 
uses createWithTimestampsLL to stream that amount to a designated receiver.

Make the NFT stream trasnferrable and cancellable.
