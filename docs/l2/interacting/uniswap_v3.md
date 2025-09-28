# Uniswap V3 on Ethrex L2

This guide shows how to deploy a canonical `WETH9`, Uniswap V3 core and periphery contracts, and run the Uniswap V3 web UI against an Ethrex L2 network. It assumes you already have an L2 running and accessible via JSON-RPC.

> [!NOTE]
> Uniswap V3 is not part of the default Ethrex L2 deployment. Operators can optionally deploy it. Review Uniswap's licenses and terms before proceeding.

## Prerequisites

- An Ethrex L2 JSON-RPC endpoint, for example `http://localhost:1729` (see [Quickstart L2](../../getting-started/quickstart-l2.md))
- A funded deployer private key on L2
- Node.js (v18+) and `pnpm` or `npm`
- `forge` (Foundry) or `hardhat` for solidity deployment and verification workflows

We will show commands using `rex` for simple deployments and `forge script` for multi-step flows. Use whichever you prefer.

Environment variables used throughout:

```sh
export L2_RPC_URL=http://localhost:1729
export DEPLOYER_PRIVKEY=<hex-private-key-without-0x>
```

## Step 1: Deploy canonical WETH9

We use the canonical WETH9 source from `solmate` or the original `WETH9.sol`. Example using `rex` with compiled bytecode:

```sh
# Compile (example using solc)
solc --bin WETH9.sol -o out/

# Deploy with rex
rex deploy --rpc-url $L2_RPC_URL $(cat out/WETH9.bin) 0 $DEPLOYER_PRIVKEY
```

Capture the resulting address as `WETH9_ADDRESS`.

Alternatively, with Foundry:

```sh
forge create --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY src/WETH9.sol:WETH9
```

## Step 2: Deploy Uniswap V3 Core

Clone Uniswap V3 core and deploy the factory and pool init code hash. The factory requires no constructor params.

```sh
git clone https://github.com/Uniswap/v3-core.git
cd v3-core
pnpm install || npm install

# Build with foundry or hardhat (choose your stack)
forge build || npm run build

# Deploy Factory
forge create --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY \
  src/UniswapV3Factory.sol:UniswapV3Factory
```

Save the address as `UNIV3_FACTORY_ADDRESS`.

Initialize the pool for a given pair and fee tier using periphery later. For now, ensure `POOL_INIT_CODE_HASH` matches the build artifacts used by the periphery. In most modern deployments this is derived from the compiled bytecode and matches upstream.

## Step 3: Deploy Uniswap V3 Periphery

Clone periphery and deploy the router(s) pointing to your factory and `WETH9_ADDRESS`.

```sh
git clone https://github.com/Uniswap/v3-periphery.git
cd v3-periphery
pnpm install || npm install

# Build
forge build || npm run build

# Example deployments
forge create --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY \
  src/NonfungibleTokenPositionDescriptor.sol:NonfungibleTokenPositionDescriptor \
  --constructor-args 1 # example arg: chain id or library config if required

forge create --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY \
  src/SwapRouter02.sol:SwapRouter02 \
  --constructor-args $UNIV3_FACTORY_ADDRESS $WETH9_ADDRESS

forge create --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY \
  src/NonfungiblePositionManager.sol:NonfungiblePositionManager \
  --constructor-args $UNIV3_FACTORY_ADDRESS $WETH9_ADDRESS \
  --libraries src/libraries/PoolAddress.sol:PoolAddress:<POOL_ADDRESS_LIB>
```

> [!TIP]
> Exact constructor arguments and library links depend on the specific commit of v3-periphery. Consult upstream READMEs and scripts in the repo you cloned to align versions and required libraries.

Record:

- `SWAP_ROUTER_02`
- `NONFUNGIBLE_POSITION_MANAGER`
- Any descriptors or quoter contracts you deploy (e.g., `QuoterV2`)

### Initialize a pool

With the `NonfungiblePositionManager`, create and initialize a pool for a token pair:

```sh
# Example using cast (Foundry) to call initialize on a pool
cast send <POOL_ADDRESS> "initialize(uint160)" <sqrtPriceX96> \
  --rpc-url $L2_RPC_URL --private-key $DEPLOYER_PRIVKEY
```

Or use the position manager helper methods to create, initialize and add liquidity in one flow.

## Step 4: Run the Uniswap Interface (UI)

The official interface expects a chain configuration mapping. You can run it locally and point to your contracts.

```sh
git clone https://github.com/Uniswap/interface.git
cd interface
pnpm install || npm install

# Configure .env.local
cat > .env.local <<EOF
NEXT_PUBLIC_CHAIN_ID=<your L2 chain id>
NEXT_PUBLIC_RPC_URL=$L2_RPC_URL
NEXT_PUBLIC_V3_FACTORY_ADDRESS=$UNIV3_FACTORY_ADDRESS
NEXT_PUBLIC_MULTICALL2_ADDRESS=<multicall-if-required>
NEXT_PUBLIC_WETH9_ADDRESS=$WETH9_ADDRESS
NEXT_PUBLIC_POSITION_MANAGER_ADDRESS=$NONFUNGIBLE_POSITION_MANAGER
NEXT_PUBLIC_SWAP_ROUTER_02_ADDRESS=$SWAP_ROUTER_02
EOF

pnpm dev || npm run dev
```

Open the local UI, connect a wallet configured for your L2 RPC, and verify swap and liquidity actions.

## Operational considerations

- Verify gas behavior and fee tiers align with your L2 chain-id and EVM fork settings.
- Pin to specific `v3-core` and `v3-periphery` commits to avoid drift.
- Consider deploying a canonical `Multicall2` for UI aggregation.
- Back up addresses and ABIs; expose them via a public JSON for your users.

## References

- Uniswap V3 Core: `https://github.com/Uniswap/v3-core`
- Uniswap V3 Periphery: `https://github.com/Uniswap/v3-periphery`
- Uniswap Interface: `https://github.com/Uniswap/interface`
- Ethrex issue tracking this doc: `https://github.com/lambdaclass/ethrex/issues/4555`


