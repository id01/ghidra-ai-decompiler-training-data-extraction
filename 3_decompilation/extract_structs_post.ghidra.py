from ghidra.program.model.data import CategoryPath
from ghidra.program.database.data import StructureDB, FunctionDefinitionDB

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.program.flatapi import FlatProgramAPI

import json

# File extension for the original source file
FILE_EXT = '.c'

# Init datatype manager
dtm = currentProgram.getDataTypeManager()

# Get dwarf datatypes in a certain file in the dwarf data (or None if no DWARF data)
def get_dwarf_types_from_file_name(fileName):
	category = dtm.getCategory(CategoryPath('/DWARF/' + fileName))
	if category is not None:
		return category.getDataTypes()
	else:
		return None

# Get dwarf datatypes for all files in the dwarf data
def get_dwarf_types():
	category = dtm.getCategory(CategoryPath('/DWARF'))
	if category is not None:
		dataTypes = []
		for category in category.getCategories():
			dataTypes += list(category.getDataTypes())
		return dataTypes
	else:
		return None

# Encode a struct definition
def encode_struct(struct):
	structDecl = [u'struct ', struct.name, u' {\n']
	for i in range(struct.getNumComponents()):
		component = struct.getComponent(i)
		fieldDecl = "  %s %s // offset:%s\n" % (component.dataType, component.getFieldName(), hex(component.offset))
		structDecl.append(unicode(fieldDecl))
	structDecl.append(u'};\n')
	return u''.join(structDecl)

# Get structs from dwarf datatypes
def get_program_structs_from_dwarf(datatypes): # fileName in DWARF file (eg test.c)
	structDecls = []
	for struct in datatypes:
		if type(struct) is StructureDB:
			structDecls.append(encode_struct(struct))
	print(u'\n'.join(structDecls))

# Get functions from dwarf datatypes
def get_function_definitions_from_dwarf(datatypes):
	funcDecls = []
	for f in datatypes:
		if type(f) is FunctionDefinitionDB:
			funcDecls.append(f.name)
	return funcDecls

# Init decompiler
ifc = DecompInterface()
options = DecompileOptions()
ifc.setOptions(options)
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

# Get variable addresses and struct names from a function from the decompiler
def get_variable_addresses_and_struct_names(decompilerResult):
	# Get high_func aspects from decompilerResult
	high_func = decompilerResult.getHighFunction()
	lsm = high_func.getLocalSymbolMap() # <-- Includes local vars
	gsm = high_func.getGlobalSymbolMap() # <-- Includes global vars
	# We sort lsm and gsm symbols by their storage address so we can get a more consistent output
	lsmSymbols = sorted(list(lsm.getSymbols()), key=lambda x: x.getStorage())
	gsmSymbols = sorted(list(gsm.getSymbols()), key=lambda x: x.getStorage())
	# Extract var declarations and structs
	localDecls = []
	globalDecls = []
	isGlobal = False
	structs = set()
	for high_symbol in lsmSymbols + [None] + gsmSymbols:
		if high_symbol is None:
			# In the boundary between local and global, set isGlobal to true
			isGlobal = True
		else:
			# Get variable declaration to relevant list
			variableStorage = high_symbol.getStorage()
			symbolSize = hex(high_symbol.getSize())
			if isGlobal:
				globalDecls.append([high_symbol.dataType.name, high_symbol.name, str(variableStorage.getMinAddress()), symbolSize])
			elif variableStorage.isStackStorage(): # Stack vars - only position matters
				localDecls.append([high_symbol.dataType.name, high_symbol.name, format(variableStorage.getStackOffset(), 'x'), symbolSize])
			else: # Other local vars - position and min address
				localDecls.append([high_symbol.dataType.name, high_symbol.name, "%s|%s" % (variableStorage.getMinAddress(), high_symbol.getPCAddress()), symbolSize])
			# Track all structs used in this function (for declaration)
			symbolType = high_symbol.getDataType()
			if type(symbolType) is StructureDB:
				structs.add(symbolType)
	# Get struct decls
	structDecls = []
	for struct in structs:
		structDecls.append(encode_struct(struct))
	# Return dict of data
	return {'local': localDecls, 'global': globalDecls, 'struct': structDecls}

def try_get_function(funcName):
	try:
		return getGlobalFunctions(funcName)[0]
	except IndexError:
		return None

# Get dwarf types from the file name
prog = FlatProgramAPI(currentProgram)
#datatypes = get_dwarf_types_from_file_name(prog.getProgramFile().getName().rsplit('.', 1)[0] + FILE_EXT)
datatypes = get_dwarf_types()
# Get functions to iterate over based on whether we got the DWARF types or not
if datatypes is None:
	funcs = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
else:
	funcs = map(try_get_function, get_function_definitions_from_dwarf(datatypes))

# Get declarations from each func
funcDeclarations = {}
funcContents = {}
for func in funcs:
	if func is not None:
		try:
			decompilerResult = ifc.decompileFunction(func, 60, monitor)
			funcName = func.getName()
			funcDeclarations[funcName] = get_variable_addresses_and_struct_names(decompilerResult)
			funcContents[funcName] = decompilerResult.getDecompiledFunction().getC()
		except Exception as e:
			print("[ERROR] On function: ", func, ":", e)

# Json dump result into json file of the same name but different extension
if datatypes is not None:
	with open(prog.getProgramFile().getPath().rsplit('.', 1)[0] + '.gdb.json', 'w') as outFile:
		json.dump({'c': funcContents, 'decls': funcDeclarations}, outFile)
else:
	with open(prog.getProgramFile().getPath().rsplit('.', 1)[0] + '.raw.json', 'w') as outFile:
		json.dump({'c': funcContents, 'decls': funcDeclarations}, outFile)