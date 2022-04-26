/* eslint-disable */
import { CellProvider, Script } from "@ckb-lumos/base";
import { hd, Indexer, config, helpers, commons, RPC } from "@ckb-lumos/lumos";
async function signAndSendTransaction(
  txSkeleton: helpers.TransactionSkeletonType,
  privatekey: string,
  rpc: RPC
): Promise<string> {
  txSkeleton = commons.common.prepareSigningEntries(txSkeleton);
  const message = txSkeleton.signingEntries.get(0)?.message;
  const Sig = hd.key.signRecoverable(message!, privatekey);
  const tx = helpers.sealTransaction(txSkeleton, [Sig]);
  const hash = await rpc.send_transaction(tx, "passthrough");
  return hash;
}
const privateKey =
  "0xe47dad11774cc3cb6fb8004b074312d49eee7f3b6005e926e2523ef47d3a8597";
const cfg = config.predefined.AGGRON4;
const rpcURL = "https://testnet.ckb.dev/rpc";
const indexerURL = "https://testnet.ckb.dev/indexer";
const indexer = new Indexer(indexerURL, rpcURL);
const rpc = new RPC(rpcURL);
const pubKey = hd.key.privateToPublic(privateKey);
const args = hd.key.publicKeyToBlake160(pubKey);
const secp256k1 = cfg.SCRIPTS["SECP256K1_BLAKE160"]!;
const lockScript = {
  code_hash: secp256k1.CODE_HASH,
  hash_type: secp256k1.HASH_TYPE,
  args: args
};
const address = helpers.generateAddress(lockScript, { config: cfg });

async function deployContract() {
  const deployOptions = {
    cellProvider: indexer as CellProvider,
    scriptBinary: Uint8Array.of(1),
    fromInfo: address,
    config: cfg
  };
  const res = await commons.deploy.generateDeployWithTypeIdTx(deployOptions);
  console.log(res);
  const txHash = await signAndSendTransaction(res.txSkeleton, privateKey, rpc);
  console.log("deploy tx hash", txHash);
}

deployContract();

async function getCellData(txHash) {
  const cell = await rpc.get_live_cell(
    {
      index: "0x0",
      tx_hash: txHash
    },
    true
  );
  console.log(cell.cell.data);
}

async function getupgradeCellData(txHash) {
  const cell = await rpc.get_live_cell(
    {
      index: "0x0",
      tx_hash: txHash
    },
    true
  );
  console.log(cell.cell.data);
}

async function upgradeContract(typeId) {

  const upgradeOption = {
    cellProvider: indexer as CellProvider,
    scriptBinary: Uint8Array.of(2),
    fromInfo: address,
    config: cfg,
    typeId: typeId
  };
  const upgradeRes = await commons.deploy.generateUpgradeTypeIdDataTx(
    upgradeOption
  );
  const txHash = await signAndSendTransaction(
    upgradeRes.txSkeleton,
    privateKey,
    rpc
  );
  console.log("upgraded tx hash", txHash);
}

// deployContract();
// getCellData(); // 01
// upgradeContract()
// getupgradeCellData(); // 02
