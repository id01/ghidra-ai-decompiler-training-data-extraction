import pandas as pd
import nostril.nostril
import multiprocessing

OUTFILE = 'compiled/original_funcs.parq'
INFILES = ['compiled/decompiled_funcs/gcc_O0_C.parq', 'compiled/decompiled_funcs/clang_O0_C.parq']

def process_parquet(parq):
	df = pd.read_parquet(parq)

	# This is quite a bit stricter than the default, so that bad code is detected as nonsense while more readable code is detected as not nonsense
	nonsense = nostril.nostril.generate_nonsense_detector(min_score=7.5)

	def sense(s):
		try:
			return not nonsense(s)
		except Exception as e:
			print("EXCEPTION: ", e)
			return False

	# Check which one of these are more readable code, pick only them
	df = df[df['original_funcs'].map(sense)]

	# Sort code by string length
	df = df.reindex(df['original_funcs'].str.len().sort_values().index)

	# Remove length outliers
	df = df.iloc[len(df)//16:-len(df)//16]

	# Remove duplicate original_funcs
	df = df.groupby('original_funcs').first().reset_index()

	# Remove funcs that are too short (<=2 statements)
#	df = df[df['decompiled_funcs'].map(lambda x: x.count(';') > 2)]
	df = df[df['original_funcs'].map(lambda x: x.count(';') > 2)]

	# Every file gets at most 5 functions (so that we don't have one file dominating everything).
	# We use sample(frac=1) to shuffle before getting the top 5
	df = df.sample(frac=1).groupby('repo_path').head(5).reset_index()

	# Write new parquet as orig.parq.parq
	return df
#	df.to_parquet(parq + '.parq', compression='GZIP')

if __name__ == "__main__":
	p = multiprocessing.Pool(len(INFILES))
	dfs = p.map(process_parquet, INFILES)
	combined = pd.concat(dfs, keys=pd.Series([x.rsplit('/', 1)[1].rsplit('.', 1)[0] for x in INFILES], name="compiler")).reset_index()
#	combined = combined.groupby(['original_funcs', 'repo_path']).sample(1).reset_index() # Get one random compiler's version of each original func (not one for each)
	combined = combined[["compiler", "original_funcs", "repo_path"]] # Get only relevant columns
	combined.to_parquet(OUTFILE, compression='GZIP')
