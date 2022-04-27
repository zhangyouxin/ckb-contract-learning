import { CellCollector, CellProvider, QueryOptions } from "@ckb-lumos/base";
import { Indexer as CkbIndexer } from "@ckb-lumos/ckb-indexer";
import { key } from "@ckb-lumos/hd";
import { generateSecp256k1Blake160Address, parseAddress } from "@ckb-lumos/helpers";

const privateKey = "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"
class PureCkbCellProvider implements CellProvider {
  readonly indexer;
  constructor(indexerUrl: string, rpcUrl: string) {
    this.indexer = new CkbIndexer(indexerUrl, rpcUrl);
  }
  collector(queryOptions: QueryOptions): CellCollector {
    return this.indexer.collector({ ...queryOptions, outputDataLenRange: ['0x0', '0x1'] });
  }
}

export async function getCells() {
  const fromAddress = generateSecp256k1Blake160Address(key.privateKeyToBlake160(privateKey));
  const fromLockscript = parseAddress(fromAddress)

  const indexer = new CkbIndexer("http://localhost:8116", "http://localhost:8114");
  const collector = indexer.collector({ lock: fromLockscript, data: "0x"})
  const cells = collector.collect();
  for await (const iterator of cells) {
    console.log(iterator);
  }
}