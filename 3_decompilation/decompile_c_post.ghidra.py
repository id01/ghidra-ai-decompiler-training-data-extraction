import json
import glob
import java.io.File
from ghidra.base.project import GhidraProject
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

# Iterate over functions, extract decompile results
result = {}
funcs = currentProgram.getFunctionManager().getFunctions(True)
prog = FlatProgramAPI(currentProgram)
fdapi = FlatDecompilerAPI(prog)
print("Processing " + prog.getProgramFile().getPath())
for func in funcs:
	if not str(func)[:12] == "<EXTERNAL>::":
		result[func.getName()] = fdapi.decompile(func)

# Json dump result into json file of the same name but different extension
with open(prog.getProgramFile().getPath().rsplit('.', 1)[0] + '.raw.json', 'w') as outFile:
	json.dump(result, outFile)
