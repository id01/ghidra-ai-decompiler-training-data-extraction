import pandas as pd
from sctokenizer import CppTokenizer, TokenType
import subprocess
import json
import msgspec
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map
import os
from path import Path
from functools import partial
import random

MIN_SIZE = 8

tokenizer = CppTokenizer()

# Combines gdb vars with raw vars
def combine_gdb_raw(gdbVars, rawVars):
	rawVars = pd.DataFrame(rawVars, columns=["rawDtype", "rawSymbol", "id", "rawSize"])
	gdbVars = pd.DataFrame(gdbVars, columns=["gdbDtype", "gdbSymbol", "id", "gdbSize"])
	combinedVars = pd.merge(rawVars, gdbVars, how='inner', on='id')
	return combinedVars

# Gets the index of an element in a list, or -1 if it does not exist
def soft_list_index(l, x):
	try:
		return l.index(x)
	except ValueError:
		return -1

# Reorders combined vars to the same order they first appear in cCode. Removes them if 
def reorder_combined_vars(combinedVars, cCode):
	# Tokenize
	tokenized = tokenizer.tokenize(cCode)
	# Replace the function name with something else
	replaced = False
	for i in range(len(tokenized)-1):
		if tokenized[i+1].token_value == "(":
			cCode = cCode.replace(tokenized[i].token_value, "FUN_%d" % random.randint(0, 99999999), 1)
			replaced = True
			break
		elif tokenized[i+1].token_value == "{":
			break
	if not replaced:
		print("Could not replace func name in ", tokenized)
	# Get order identifiers from function, reorder vars
	identifiers = [x.token_value for x in tokenized if x.token_type == TokenType.IDENTIFIER]
	combinedVars["order"] = combinedVars["rawSymbol"].map(lambda symbol: soft_list_index(identifiers, symbol))
	combinedVars = combinedVars.sort_values("order", axis="rows")
	return combinedVars[combinedVars["order"] >= 0], cCode

# Preprocesses a single program
def preprocess_object(compiler, repopath):
#	print(compiler, repopath)
	# Load dwarf data
	path = "compiled/decompiled_funcs/%s/%s" % (compiler, repopath)
	stdout, _ = subprocess.Popen(["dwarfdump", "-s", path + '.o'], stdout=subprocess.PIPE).communicate()
	dwarfStrings = []
	for col in stdout.split(b"\n"):
		if len(col) > 0: # and not col.startswith(b".debug_str"):
			try:
				dwarfStrings.append(col.split(b"'", 1)[1].removesuffix(b"'").decode('utf-8'))
			except:
				pass # Bad column, probably section header. Ignore
#				print("ERROR ON COL ", col)
#	print(dwarfStrings)
	dwarfStrings = set(dwarfStrings)
	# Load gdb/raw json files
	with open(path + '.gdb.json', 'r') as gdbFile:
		gdbJson = json.load(gdbFile)
	with open(path + '.raw.json', 'r') as rawFile:
		rawJson = json.load(rawFile)
	# Init samples
	samples = []
	# Iterate over functions
	for func in gdbJson["decls"].keys():
		# Extract relevant vars from json if possible
		try:
			gdbDecls = gdbJson["decls"][func]
			rawDecls = rawJson["decls"][func]
			rawC = rawJson["c"][func]
			valid = True
		except KeyError:
			valid = False
		# If we were able to extract the func...
		if valid:
			# Merge the local vars, remove the vars not in DWARF, and reorder them to be in the same order as they first appear in the decompiled C code
			combinedLocal = combine_gdb_raw(gdbDecls["local"], rawDecls["local"])
			if len(combinedLocal) > 0:
				combinedLocal = combinedLocal[combinedLocal["gdbSymbol"].map(lambda x: x in dwarfStrings)] # Filter for only GDB vars which appear in dwarf strings (and not the automatically generated ones)
				combinedLocal, rawC = reorder_combined_vars(combinedLocal, rawC)
			# Merge the global vars, remove the vars not in DWARF, and reorder them to be in the same order as they first appear in the decompiled C code
			combinedGlobal = combine_gdb_raw(gdbDecls["global"], rawDecls["global"])
			if len(combinedGlobal) > 0:
				combinedGlobal = combinedGlobal[combinedGlobal["gdbSymbol"].map(lambda x: x in dwarfStrings)] # Filter for only GDB vars which appear in dwarf strings (and not the automatically generated ones)
				combinedGlobal, rawC = reorder_combined_vars(combinedGlobal, rawC)
			# Write the structs and vars in a standardized format
			if len(combinedLocal) > 0 and len(combinedGlobal) > 0:
				wantedResults = ['The original, readable, pre-compilation version of this decompiled code uses the following structs and variables:\n```']
				# Structs
				wantedResults.append("// Structs")
				if len(gdbDecls["struct"]) > 0:
					wantedResults.append('\n'.join(gdbDecls["struct"]))
				else:
					wantedResults.append("// The pre-compilation version does not use any structs.")
				# Variables
				wantedResults.append("\n// Variables")
				if len(combinedLocal) > 0:
					for i in range(len(combinedLocal)):
						row = combinedLocal.iloc[i]
						wantedResults.append("%s %s; // was %s" % (row["gdbDtype"], row["gdbSymbol"], row["rawSymbol"]))
				else:
					valid = False # Should have at least one variable
#				if len(combinedLocal) > 0:
#					if len(wantedResults) > 0:
#						wantedResults.append("```")
#					wantedResults.append("Locals:\n```")
#					for i in range(len(combinedLocal)):
#						row = combinedLocal.iloc[i]
#						wantedResults.append("%s %s; // %s" % (row["gdbDtype"], row["gdbSymbol"], row["rawSymbol"]))
#				if len(combinedGlobal) > 0:
#					if len(wantedResults) > 0:
#						wantedResults.append("```")
#					wantedResults.append("Globals:\n```")
#					for i in range(len(combinedGlobal)):
#						row = combinedGlobal.iloc[i]
#						wantedResults.append("%s %s; // %s" % (row["gdbDtype"], row["gdbSymbol"], row["rawSymbol"]))
				# Add the sample to the dataset if it is valid
				if valid:
					wantedResults.append("```")
					samples.append(["```\n%s\n```" % rawC.strip('\n\t '), '\n'.join(wantedResults)])
	# Create new dataframe
	samples = pd.DataFrame(samples, columns=["decompiled_funcs", "decls"])
	samples["repo_path"] = repopath
	samples["compiler"] = compiler
	return samples

def preprocess_object_try(d, dc):
	try:
		if os.stat(dc).st_size > MIN_SIZE:
#					try:
			repo = "/".join(dc.parent.parts()[4:])
			preprocessed = preprocess_object(d.name, repo + os.sep + dc.name.rsplit('.',2)[0])
			if len(preprocessed) > 0:
				return preprocessed
#				data.append(preprocessed)
#					except:
#						print("[ERROR]: ", dc)
	except FileNotFoundError:
		pass
	return None

# Preprocess all programs in 
if __name__ == "__main__":
	decoder = msgspec.json.Decoder()
	hashes = set()
	data = []
	for d in Path("compiled/decompiled_funcs").dirs():
		try:
#			if "top100" not in d:
			files = [f for f in d.walkfiles() if f.endswith(".gdb.json")]
			data += [x for x in process_map(partial(preprocess_object_try, d), files, max_workers=8, chunksize=16) if x is not None]
		except Exception as e:
			print("EXCEPTION", e, "on", d)
	pd.concat(data).to_parquet("compiled/decompiled_funcs.parq", compression="GZIP")