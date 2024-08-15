from path import Path
import pandas as pd
from rich import print
from tqdm import tqdm
import msgspec
import hashlib
import os

MIN_SIZE = 8

if __name__ == "__main__":
    decoder = msgspec.json.Decoder()
    hashes = set()
    for d in Path("compiled/decompiled_funcs").dirs():
        files = [f for f in d.walkfiles() if f.endswith(".o")]
        data = []
        for dc in tqdm(files):
            repo = "/".join(dc.parent.parts()[4:])
            orig = Path("compiled/original_funcs") / repo / (dc.name.rsplit('.',1)[0] + '.json') #d / repo / (dc.name.rsplit('.',1)[0] + '.orig')
            try:
                if os.stat(orig).st_size > MIN_SIZE:
                    try:
#                        dc_js = decoder.decode(dc.read_bytes())
                        orig_js = decoder.decode(orig.read_bytes())
                        for func in orig_js:
                            try:
#                                app = (dc_js[func], orig_js[func], repo + os.sep + dc.name)
                                app = (orig_js[func], repo + os.sep + dc.name)
                                if (dc_hash := hashlib.md5(app[0].encode('utf-8'))) not in hashes:
                                    hashes.add(dc_hash)
                                    data.append(app)
                            except:
                                continue
                    except:
                        print("[ERROR]: ", [dc, orig])
            except FileNotFoundError:
                pass
        df = pd.DataFrame(data, columns=["original_funcs", "repo_path"])
        df.to_parquet(d + ".parq", compression="GZIP")
