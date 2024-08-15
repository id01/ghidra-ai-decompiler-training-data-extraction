import glob
import os

# Renames ghcc binaries to include '.o'
files = glob.glob("compiled/decompiled_funcs/ghcc_top100/*/*/*")
for f in files:
	if not f.endswith((".json", ".o")):
		os.rename(f, f + '.o')
		print(f)