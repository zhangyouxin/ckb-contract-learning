import { Script, HexString, helpers, core, toolkit, config, utils, BI, hd, RPC, Indexer, Cell } from "@ckb-lumos/lumos";
import pTimeout from 'p-timeout';

type SigningEntry = {
  script: Script;
  index: number;
  witnessArgItem: HexString;
  signatureOffset: number;
  signatureLength: number;
  message: HexString;
};

type Promisible<T> = T | Promise<T>;

type Signature = HexString;

interface SignableScript {
  generateSigningEntries: (tx: helpers.TransactionSkeletonType) => Promisible<SigningEntry[]>;
  sign: (message: HexString) => Promisible<Signature>;
}

interface Signer {
  sign: (message: HexString) => Promisible<Signature>;
}

export class PrivateKeySigner implements Signer {
  private _privateKey: HexString;

  constructor(privateKey: HexString) {
    this._privateKey = privateKey;
  }

  sign(message: HexString): Signature {
    return hd.key.signRecoverable(message, this._privateKey);
  }
}

const ALICE_PRIVATE_KEY = "0x888e22145fdc41297ab7d804771cd042e5bcb6ed7ae7d36428e72c6df389ae37";
const ALICE_ARGS = "0xf1251ee1c665f8771834983dcdb355d9ce1afd51";
const BOB_PRIVATE_KEY = "0x55630faf438e8348db78c611a4eb0064af882dc60007e314df5482fa3b4e88f6";
const BOB_ARGS = "0x521571da5d51794e3c7ed1d092eef6c652584a5a";

export class Secp256k1Blake160SignableScript implements SignableScript {
  private readonly _config: config.Config;
  private readonly _signer: Signer;

  constructor(userConfig?: config.Config, userSigner?: Signer) {
    this._config = userConfig || config.predefined.AGGRON4 as config.Config;
    this._signer = userSigner || new PrivateKeySigner(ALICE_PRIVATE_KEY);
  }

  generateSigningEntries(txSkeleton: helpers.TransactionSkeletonType): SigningEntry[] {
    let signingEntries: SigningEntry[] = [];
    const template = this._config.SCRIPTS['SECP256K1_BLAKE160'];
    let processedArgs = new Set<string>();
    const tx = helpers.createTransactionFromSkeleton(txSkeleton);
    const txHash = utils.ckbHash(
      core.SerializeRawTransaction(toolkit.normalizers.NormalizeRawTransaction(tx))
    ).serializeJson();
    const inputs = txSkeleton.get("inputs");
    const witnesses = txSkeleton.get("witnesses");
    for (let i = 0; i < inputs.size; i++) {
      const input = inputs.get(i)!;
      if (
        template.CODE_HASH === input.cell_output.lock.code_hash &&
        template.HASH_TYPE === input.cell_output.lock.hash_type &&
        !processedArgs.has(input.cell_output.lock.args)
      ) {
        processedArgs = processedArgs.add(input.cell_output.lock.args);
        const lockHash = utils.computeScriptHash(input.cell_output.lock)
        const hasher = new utils.CKBHasher();
        hasher.update(txHash);
        if (i >= witnesses.size) {
          throw new Error(`Can't find witness for input ${i}, witnesses are ${witnesses.toArray()}`);
        }
        hashWitness(hasher, witnesses.get(i)!);
        for (let j = i + 1; j < inputs.size && j < witnesses.size; j++) {
          const otherInput = inputs.get(j)!;
          if (
            lockHash.toLowerCase() === utils.computeScriptHash(otherInput.cell_output.lock).toLowerCase()
          ) {
            hashWitness(hasher, witnesses.get(j)!);
          }
        }
        for (let j = inputs.size; j < witnesses.size; j++) {
          hashWitness(hasher, witnesses.get(j)!);
        }
        const signingEntry: SigningEntry = {
          script: input.cell_output.lock,
          index: i,
          witnessArgItem: witnesses.get(i)!,
          signatureOffset: 0,
          signatureLength: 65,
          message: hasher.digestHex(),
        };
        signingEntries = signingEntries.concat(signingEntry);
      }
    }
    return signingEntries;
  }

  async sign(message: string): Promise<HexString>{
    return await this._signer.sign(message);
  }
}

export function hashWitness(hasher: any, witness: HexString): void {
  const lengthBuffer = new ArrayBuffer(8);
  const view = new DataView(lengthBuffer);
  const witnessHexString = BI.from(new toolkit.Reader(witness).length()).toString(16);
  if (witnessHexString.length <= 8) {
    view.setUint32(0, Number("0x" + witnessHexString), true);
    view.setUint32(4, Number("0x" + "00000000"), true);
  }

  if (witnessHexString.length > 8 && witnessHexString.length <= 16) {
    view.setUint32(0, Number("0x" + witnessHexString.slice(-8)), true);
    view.setUint32(4, Number("0x" + witnessHexString.slice(0, -8)), true);
  }
  hasher.update(lengthBuffer);
  hasher.update(witness);
}

const rpcUrl = "https://testnet.ckb.dev/rpc";
const indexerUrl = "https://testnet.ckb.dev/indexer";

const getBalance = async (lockArgs: string) => {
  const indexer = new Indexer(indexerUrl, rpcUrl);
  const ckbCollector = indexer.collector({
    lock: {
      code_hash: config.predefined.AGGRON4.SCRIPTS.SECP256K1_BLAKE160.CODE_HASH,
      hash_type: config.predefined.AGGRON4.SCRIPTS.SECP256K1_BLAKE160.HASH_TYPE,
      args: lockArgs,
    },
    type: "empty",
    outputDataLenRange: ["0x0", "0x1"],
  });

  let balance = BI.from(0)
  for await (const cell of ckbCollector.collect()) {
    balance = balance.add(cell.cell_output.capacity);
  }
  return balance.div(100000000).toString();
}

const transferCkb = async (senderPrivateKey: HexString, receiverLockArgs: string, capacity: BI) => {
  const userConfig = config.predefined.AGGRON4;
  const rpc = new RPC(rpcUrl);
  const indexer = new Indexer(indexerUrl, rpcUrl);
  const signer = new PrivateKeySigner(senderPrivateKey);
  const signableScript = new Secp256k1Blake160SignableScript(config.predefined.AGGRON4, signer);
  let txSkeleton = helpers.TransactionSkeleton({ cellProvider: indexer });
  
  const pubKey = hd.key.privateToPublic(senderPrivateKey)
  const args = hd.key.publicKeyToBlake160(pubKey);
  const lockScript = {
    code_hash: userConfig.SCRIPTS.SECP256K1_BLAKE160.CODE_HASH,
    hash_type: userConfig.SCRIPTS.SECP256K1_BLAKE160.HASH_TYPE,
    args,
  };
  const ckbCollector = indexer.collector({
    lock: lockScript,
    type: "empty",
    outputDataLenRange: ["0x0", "0x1"],
  });

  const collectedCells: Cell[] = []
  let totalInput = BI.from(0)
  for await (const cell of ckbCollector.collect()) {
    collectedCells.push(cell);
    totalInput = totalInput.add(cell.cell_output.capacity);
  }

  const transferOutput: Cell = {
    cell_output: {
      capacity: capacity.mul(100000000).toHexString(),
      lock: {
        code_hash: userConfig.SCRIPTS.SECP256K1_BLAKE160.CODE_HASH,
        hash_type: userConfig.SCRIPTS.SECP256K1_BLAKE160.HASH_TYPE,
        args: receiverLockArgs,
      },
    },
    data: "0x",
  };

  const changeOutput: Cell = {
    cell_output: {
      capacity: totalInput.sub(capacity.mul(100000000)).sub(1000).toHexString(),
      lock: lockScript,
    },
    data: "0x",
  };

  txSkeleton = txSkeleton.update("inputs", (inputs) => inputs.push(...collectedCells));
  txSkeleton = txSkeleton.update("outputs", (outputs) => outputs.push(transferOutput, changeOutput));
  txSkeleton = txSkeleton.update("cellDeps", (cellDeps) =>
    cellDeps.push({
      out_point: {
        tx_hash: userConfig.SCRIPTS.SECP256K1_BLAKE160.TX_HASH,
        index: userConfig.SCRIPTS.SECP256K1_BLAKE160.INDEX,
      },
      dep_type: userConfig.SCRIPTS.SECP256K1_BLAKE160.DEP_TYPE,
    })
  );
  const witness = new toolkit.Reader(
    core.SerializeWitnessArgs(toolkit.normalizers.NormalizeWitnessArgs({
      lock: `0x${'00'.repeat(65)}`,
    }))
  ).serializeJson();
  txSkeleton = txSkeleton.update("witnesses", (witnesses) => witnesses.push(witness));

  const signingEntries = signableScript.generateSigningEntries(txSkeleton)
  console.log("signingEntries", signingEntries);

  const message = signingEntries[0].message;
  const signature = await signableScript.sign(message);
  console.log("signature", signature);

  const tx = helpers.createTransactionFromSkeleton(txSkeleton);
  tx.witnesses[0] = new toolkit.Reader(
    core.SerializeWitnessArgs(toolkit.normalizers.NormalizeWitnessArgs({
      lock: signature,
    }))
  ).serializeJson();
  console.log("tx is:", tx);
  
  console.log("Before transfer, sender balance is:", await getBalance(lockScript.args), "reciver balance is:", await getBalance(receiverLockArgs));
  
  const txHash = await rpc.send_transaction(tx, "passthrough");
  console.log("The transaction hash is", txHash);

  const checkTxCommitted = async () => {
    const txPromise = rpc.get_transaction(txHash);
    const tx = await pTimeout(txPromise, 10000);
    if (tx?.tx_status?.status === 'committed') {
      return true;
    }
    await new Promise((resolve, reject) => setTimeout(resolve, 5000));
    return false;
  };

  // eslint-disable-next-line no-constant-condition
  while(true){
    const commited = await checkTxCommitted()
    if (commited) {
      console.log("The tx is commited!!!");
      break;
    }
    console.log("Waiting for the tx to be commited...");
  }

  console.log("After transfer, sender balance is:", await getBalance(lockScript.args), "reciver balance is:", await getBalance(receiverLockArgs));
  
}

transferCkb(ALICE_PRIVATE_KEY, BOB_ARGS, BI.from(100))
// run(BOB_PRIVATE_KEY, ALICE_ARGS, BI.from(65))