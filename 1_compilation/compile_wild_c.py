import pandas as pd
import sys
import subprocess
import os
import shutil
import resource
import tempfile

COMPILE_TIMEOUT = 30 # Compile timeout in seconds
MAX_VIRTUAL_MEMORY = 8*1024*1024*1024 # 8 GB max for subprocess memory usage (so one compiled code going rogue does not crash our chain)
TEMPFILE_PREFIX = "AIDEC"
KERNEL_VERSION = "6.8.1-arch1-1"
WANTED_EXT = ".o"

keepAllFiles = False # Default keepAllFiles is false (this is whether you should keep files other than WANTED_EXT files)
# MINGW GCC -O0 i686 (Linux)
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/mingw_i686_gcc_O0_1M'
#CC = ['i686-w64-mingw32-gcc'] # C compiler
#CXX = ['i686-w64-mingw32-g++'] # C++ compiler
#FLAGS = ["-c"] # Flags
# GCC -O0
#OUTPUT_DIR = '/fast/user/compiled/decompiled_funcs/gcc_O0_C'
#CC = ['gcc'] # C compiler
#CXX = ['g++'] # C++ compiler
#CXX = None
#FLAGS = ["-c", "-Wfatal-errors", "-gdwarf-4"] # Flags. Stop after 1 error, build with DWARF 4
#FLAGS = ["-c", "-Wfatal-errors", "-I/lib/modules/%s/build/include" % KERNEL_VERSION, "-D__KERNEL__", "-DMODULE"] # Flags. Stop after 1 error, configure kernel module headers (didn't work as I would have liked with atomic64)
# GCC -Os
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/gcc_Os_1M'
#CC = ['gcc'] # C compiler
#CXX = ['g++'] # C++ compiler
#FLAGS = ["-c", "-Os"] # Flags
# GCC -O2
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/gcc_O2_1M'
#CC = ['gcc'] # C compiler
#CXX = ['g++'] # C++ compiler
#FLAGS = ["-c", "-O2"] # Flags
# Clang -O0
OUTPUT_DIR = '/fast/user/compiled/decompiled_funcs/clang_O0_C'
CC = ['clang'] # C compiler
CXX = ['clang++'] # C++ compiler
FLAGS = ["-c", "-O0", "-Wfatal-errors", "-gdwarf-4"] # Flags
# Clang -Os
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/clang_Os_1M'
#CC = ['clang'] # C compiler
#CXX = ['clang++'] # C++ compiler
#FLAGS = ["-c", "-Os"] # Flags
# Clang -O2
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/clang_O2_1M'
#CC = ['clang'] # C compiler
#CXX = ['clang++'] # C++ compiler
#FLAGS = ["-c", "-O2"] # Flags
# MSVC -O2 with EHa (Exception handing asynchronous, with Windows exceptions)
#OUTPUT_DIR = os.path.expanduser("~") + "\\msvc_O2_EHa_1M"
#CC = ['procgov64', '--maxmem', '1G', 'cl'] # C compiler
#CXX = ['procgov64', '--maxmem', '1G', 'cl'] # C++ compiler
#FLAGS = ["/EHac", "/O2"] # Flags
#WANTED_EXT = ".obj"
# Parser only
#OUTPUT_DIR = '/home/user/Desktop/projects/ai_decompiler/compiled/original_funcs'
#CC = ['python', '/home/user/Desktop/projects/ai_decompiler_2/1_compilation/unpack_c.py'] # C compiler
#CXX = None
#CXX = ['python', '/home/user/Desktop/projects/ai_decompiler_2/1_compilation/unpack_c.py'] # C++ compiler
#FLAGS = [] # Flags
#keepAllFiles = True
#WANTED_EXT = ".json"

# Function to limit max virtual memory
def limit_virtual_memory():
	resource.setrlimit(resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, resource.RLIM_INFINITY))

# Function to validate row
def validate_row_contents(t):
	if '#include "' in t: # Includes relative path. This will not compile, so skip it to save time.
		return False
	if '#include <linux/' in t: # Include linux module. Unfortunately, I don't have the compilation method for this yet.
		return False
	return True

# Function to preprocess row contents
def preprocess_row_contents(t):
	# Remove ifdef/endif construct
	if t.startswith("#ifdef") and t.endswith("#endif"):
		t = t.rsplit('\n', 1)[-1].split('\n', 1)[0]
#	t = t.replace("#include <linux/atomic.h>\n", "#include <asm/atomic64.h>\n#include<linux/atomic.h>\n")
	return t

workingDir = tempfile.TemporaryDirectory(prefix=TEMPFILE_PREFIX)
if not os.path.isdir(OUTPUT_DIR):
	try:
		os.mkdir(OUTPUT_DIR)
	except Exception:
		pass
	
df = pd.read_parquet(sys.argv[1])

for group_name, df_group in df.groupby('repo'):
#	repoSize = 0
#	isCpp = False
#	for row_index, row in df_group.iterrows():
#		repoSize += row['size']
#		if row['name'].endswith(('.hpp', '.cpp')):
#			isCpp = True
#		if repoSize > REPO_SIZE_LIMIT:
#			break
#	if repoSize > REPO_SIZE_LIMIT:
#		print("Skipping", group_name, ": too large")
#	else:
	sys.stdout.write("Compiling %s... " % group_name)
	# Check if file is already compiled.
	repoName = group_name.replace('/', '_').replace('\\', '_')
	if os.path.exists(os.path.join(OUTPUT_DIR, repoName)):
		print("Already exists, skipping")
	else:
		# Export files and get list of them to compile.
		filesByExtension = {".c": [], ".cpp": []}
		compileDir = os.path.join(workingDir.name, repoName)
		if not os.path.isdir(compileDir):
			os.mkdir(compileDir)
		os.chdir(compileDir)
		for row_index, row in df_group.iterrows():
			ext = None
			if row['name'].endswith(".c"):
				ext = ".c"
			elif row['name'].endswith(".cpp"):
				ext = ".cpp"
			if ext is not None:
				if validate_row_contents(row['contents']):
					with open(row['name'], 'w', encoding='utf-8') as f:
						# Preprocess row contents
						f.write(preprocess_row_contents(row['contents']))
						filesByExtension[ext].append(row['name'])
		# Try to compile each file into an object file individually
		for ext, files in filesByExtension.items():
			compiler = None
			if ext == ".c":
				compiler = CC
			elif ext == ".cpp" and CXX is not None:
				compiler = CXX
			if compiler is not None:
				try:
					subprocess.run(compiler + FLAGS + files, check=True, timeout=COMPILE_TIMEOUT, preexec_fn=limit_virtual_memory)
					print("SUCCESS")
				except subprocess.CalledProcessError:
					print("FAILED")
				except subprocess.TimeoutExpired:
					print("TIMEOUT")
					break
		# Remove all non-object files (comment out if generating data for original funcs)
		if not keepAllFiles:
			for f in os.listdir('.'):
				if not f.endswith(WANTED_EXT):
					try:
						os.unlink(f)
					except Exception:
						pass
		# Return to working dir
		os.chdir(workingDir.name)
		# Move the dir over to the output dir
		try:
			shutil.move(compileDir, OUTPUT_DIR + os.sep)
		except shutil.Error:
			print("Can't save, already exists")
