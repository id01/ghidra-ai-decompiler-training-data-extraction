import clang
import clang.cindex
from clang.cindex import CursorKind
import sys
import subprocess
import os
import json
from intervaltree import Interval, IntervalTree

FILESIZE_LIMIT = 100 * 1000 # If a source file is greater than 100KB, that is a very bad sign
generateAll = False

def fully_qualified(c):
	if c is None:
		return ''
	elif c.kind == CursorKind.TRANSLATION_UNIT:
		return ''
	else:
		res = fully_qualified(c.semantic_parent)
		if res != '':
			return res + '::' + c.spelling
	return c.spelling

FUNC_CURSOR_KINDS = [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR]
def kind_valid(x):
	try:
		return x.kind in FUNC_CURSOR_KINDS
	except ValueError:
		return False

#INFO_CURSOR_KINDS = [CursorKind.STRUCT_DECL, CursorKind.CLASS_DECL, CursorKind.TYPEDEF_DECL, CursorKind.ENUM_DECL]
#def info_kind_valid(x):
#	try:
#		return x.kind in INFO_CURSOR_KINDS
#	except ValueError:
#		return False

# Preprocesses a c/cpp file with a certain compiler for eventual function extraction. Also checks if file is actually good
def preprocess_file(f, outFile):
	if os.stat(f).st_size < FILESIZE_LIMIT:
		with open(f, 'rb') as inFileH:
			inFile = inFileH.read()
			# Should not contain #define macros or #ifdefs or #if
			if b'#define' not in inFile and b'#if' not in inFile:
				# Should be in English (ASCII)
				try:
					inFileAscii = inFile.decode('ascii')
					# Preprocess, write result, and return success
					preprocessed, _ = subprocess.Popen(["clang-format", "-style=llvm"], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(input=inFile)
					outFile.write(preprocessed)
					return True
				except UnicodeDecodeError:
					pass
	# Return fail
	return False

# Get relevant portions from func
REF_KINDS = [CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR, CursorKind.TYPE_REF] # Also CursorKind.UNEXPOSED_EXPR sometimes for class I believe
REF_TARGET_KINDS = [CursorKind.STRUCT_DECL, CursorKind.CLASS_DECL, CursorKind.TYPEDEF_DECL, CursorKind.ENUM_DECL, CursorKind.VAR_DECL]
def get_function_source_with_refs(source, funcCursor):
	# Get ref intervals # NOTE: We remove these because they are guessed by the first-stage DWARF guesser now
#	t = IntervalTree()
#	for x in funcCursor.walk_preorder():
#		if x.kind in REF_KINDS:
#			xDef = x.get_definition()
#			if xDef is not None and xDef.kind in REF_TARGET_KINDS and xDef.extent.start.file is not None and xDef.extent.start.file.name == funcCursor.extent.start.file.name:
#				intervalStart = x.get_definition().extent.start.offset
#				intervalEnd = x.get_definition().extent.end.offset
#				if intervalStart != intervalEnd:
#					t[intervalStart : intervalEnd] = True
#				else:
#					pass # Probably some sort of macro that doesn't exist, just ignore it
	# Add function interval
#	t[funcCursor.extent.start.offset : funcCursor.extent.end.offset] = True
	# Merge
#	t.merge_overlaps()
	# Put sorted intervals in a string
#	elems = []
#	for interval in sorted(t):
#		if interval.end < len(source) and source[interval.end] == 59: # Semicolon after interval.end (useful for struct declarations)
#			elems.append(source[interval.begin:interval.end+1])
#		else:
#			elems.append(source[interval.begin:interval.end])
#	return b'\n\n'.join(elems)
	return source[funcCursor.extent.start.offset : funcCursor.extent.end.offset]

# Get relevant portions from file
'''
Inspect all elements in cursor with this:

source = open('test.cpp', 'rb').read()
idx = clang.cindex.Index.create()
tu = idx.parse('test.cpp', options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
cursors = [x for x in tu.cursor.walk_preorder() if x.extent.start.file is not None and x.extent.start.file.name == 'test.cpp']
[(x.kind, source[x.extent.start.offset : x.extent.end.offset].decode('utf-8')) for x in cursors]
'''
def get_funcs(cFile):
	with open(cFile, 'rb') as cF:
		source = cF.read()
	idx = clang.cindex.Index.create()
	tu = idx.parse(cFile, options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD) # Need detailed processing record for #defines
	funcs = {fully_qualified(x): get_function_source_with_refs(source, x).decode('utf-8') for x in tu.cursor.walk_preorder() if x.extent.start.file is not None and x.extent.start.file.name == cFile and kind_valid(x)}
	# Remove all funcs without any comments or with too few statements (2 or less)
	return {k: v for k, v in funcs.items() if v.count(';') > 2}

def preprocess_funcs(fileName):
	if not fileName.endswith((".pp.c", ".pp.cpp")):
		fileNameWithoutExt = fileName.rsplit('.', 1)[0]
		outFileName = fileNameWithoutExt + '.json'
		try:
			if os.stat(fileNameWithoutExt + '.c').st_size < FILESIZE_LIMIT:
				cFile = fileNameWithoutExt + '.pp.c'
				goodFile = False
				if generateAll or not os.path.isfile(cFile):
					with open(cFile, 'wb') as out:
						goodFile = preprocess_file(fileNameWithoutExt + '.c', out)
				if goodFile and (generateAll or not os.path.isfile(outFileName)):
					with open(outFileName, 'w') as out:
						json.dump(get_funcs(cFile), out)
		except FileNotFoundError:
			pass
		try:
			if os.stat(fileNameWithoutExt + '.cpp').st_size < FILESIZE_LIMIT:
				cppFile = fileNameWithoutExt + '.pp.cpp'
				goodFile = False
				if generateAll or not os.path.isfile(cppFile):
					with open(cppFile, 'wb') as out:
						goodFile = preprocess_file(fileNameWithoutExt + '.cpp', out)
				if goodFile and (generateAll or not os.path.isfile(outFileName)):
					with open(outFileName, 'w') as out:
						json.dump(get_funcs(cppFile), out)
		except FileNotFoundError:
			pass

def write_preprocessed_funcs(fileName):
	try:
		if fileName.endswith(".c"): # Only C files for now
			preprocess_funcs(fileName)
	except Exception as e:
		print("EXCEPTION: ", e)

if __name__ == "__main__":
	for fileName in sys.argv[1:]:
		write_preprocessed_funcs(fileName)