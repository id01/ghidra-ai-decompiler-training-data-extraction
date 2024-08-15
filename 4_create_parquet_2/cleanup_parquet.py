import pandas as pd
#from fuzzywuzzy.process import dedupe
#from fuzzywuzzy import fuzz

df = pd.read_parquet("compiled/decompiled_funcs.parq")
# Filter for long enough outputs (which actually have content compared to being mostly stripped)
#df = df[df['decls'].str.len() > 250] <-- doesn't remove that many anymore (only 10%)
# Remove outputs that have the exact same decls if there are more than 2
df = df.groupby('decls').head(2).reset_index() # <-- only 31k with 1, 42k with 2. We don't want too many duplicates here or we get bias.
# Remove outputs that have too similar decls
#dedupedDecls = set(dedupe(list(df['decls']), threshold=90, scorer=fuzz.ratio))
df.to_parquet("compiled/decompiled_funcs_clean.parq")