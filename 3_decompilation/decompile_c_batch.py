import glob
import queue
import subprocess
import threading
import binascii
import os
import shutil
import tempfile
import resource
import sys

BATCH_SIZE = 8 # Number of .o/.obj files to analyze for each ghidra-analyzeHeadless run
TEMPFILE_PREFIX = "AIDECGHI" # Prefix for tempfiles
GHIDRA_PROJECT_DIR = '/tmp/aidecGhidraProject' # Directory to put ghidra projects in

FILEEXT = '.o' # File extension to decompile
# Fill toDecompile queue
toDecompile = queue.Queue()
for x in glob.glob('compiled/decompiled_funcs/ghcc_top100/*/*/*' + FILEEXT):
	toDecompile.put(x)
#import pandas as pd
#for rp in pd.read_parquet('compiled/decompiled_funcs/gcc_O0_C.parq.parq').groupby('repo_path').first().index:
#	toDecompile.put('compiled/decompiled_funcs/gcc_O0_C/' + rp.rsplit('.', 1)[0] + FILEEXT)
#import pandas as pd
#origDf = pd.read_parquet('compiled/original_funcs.parq').groupby('repo_path').first()
#for rp in origDf.index:
#	if origDf.loc[rp]['compiler'] == "gcc_O0_C":
#		toDecompile.put('compiled/decompiled_funcs/' + origDf.loc[rp]['compiler'] + '/' + rp.rsplit('.', 1)[0] + FILEEXT)

# For decompile with GDB
GDB_OUTEXT = '.gdb.json' # Output file extension generated
GDB_POST_SCRIPT = os.path.dirname(__file__) + '/extract_structs_post.ghidra.py'
GDB_PRE_SCRIPT = None

# For decompile without GDB
RAW_OUTEXT = '.raw.json' # Output file extension generated
RAW_POST_SCRIPT = os.path.dirname(__file__) + '/extract_structs_post.ghidra.py'
RAW_PRE_SCRIPT = os.path.dirname(__file__) + '/disable_dwarf_loading_pre.ghidra.py'

# Run in gdb/non-gdb mode
#pid = os.fork()
#if pid > 0: # Parent process, do raw reversing
if sys.argv[1] !=  "--gdb":
	print("Running in non-GDB mode")
	OUTEXT = RAW_OUTEXT
	POST_SCRIPT = RAW_POST_SCRIPT
	PRE_SCRIPT = RAW_PRE_SCRIPT
else: # Child process, do GDB reversing
	print("Running in GDB mode")
	OUTEXT = GDB_OUTEXT
	POST_SCRIPT = GDB_POST_SCRIPT
	PRE_SCRIPT = GDB_PRE_SCRIPT

# Make ghidra project dir
try:
	os.mkdir(GHIDRA_PROJECT_DIR)
except:
	pass

# Function to limit max virtual memory
MAX_VIRTUAL_MEMORY = 12*1024*1024*1024 # 4 GB max for subprocess memory usage (so one compiled code going rogue does not crash our chain)
def limit_virtual_memory():
	resource.setrlimit(resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, resource.RLIM_INFINITY))

# Convert o file name to json file name
def add_ext(o):
	return o.rsplit('.', 1)[0] + OUTEXT

# Decompile (possibly in background thread) until nothing left in toDecompile queue
def decompile_thread():
	# Create temporary dir in each thread
	workingDir = tempfile.TemporaryDirectory(prefix=TEMPFILE_PREFIX)
	# Loop until queue empty
	while True:
		# Get at most BATCH_SIZE items from queue, note down if the queue was emptied
		# Copy these files to a standard filename of numbers (so that Ghidra can import files with weird names)
		emptied = False
		files = {}
		try:
			while len(files) < BATCH_SIZE:
				filename = toDecompile.get_nowait()
				if not os.path.exists(add_ext(filename)):
					tempFilename = workingDir.name + os.sep + str(len(files)) + FILEEXT
					shutil.copyfile(filename, tempFilename)
					files[tempFilename] = filename
		except queue.Empty:
			emptied = True
		# Run Ghidra
		if len(files) > 0:
			args = ['ghidra-analyzeHeadless', GHIDRA_PROJECT_DIR, binascii.hexlify(os.urandom(16)).decode('ascii'), '-import'] + list(files.keys()) + ['-deleteProject']
			if POST_SCRIPT is not None:
				args += ['-postScript', POST_SCRIPT]
			if PRE_SCRIPT is not None:
				args += ['-preScript', PRE_SCRIPT]
			subprocess.run(args, preexec_fn=limit_virtual_memory)
		# Copy json files from temporary number files back to original position
		for tempFilename, filename in files.items():
			try:
				shutil.copyfile(add_ext(tempFilename), add_ext(filename))
				print("Completed", add_ext(filename))
			except FileNotFoundError:
				print("ERROR on", add_ext(filename))
		# Remove temporary files
		for tempFilename in files.keys():
			os.unlink(tempFilename)
		# If queue was emptied, return
		if emptied:
			return

if __name__ == "__main__":
	threads = [] # Background threads
	for i in range(3): # Threads = (this number (background threads) + 1 (main thread))
		threads.append(threading.Thread(target=decompile_thread, args=()))
		threads[i].start()
	decompile_thread() # Also run thread on main thread
	# Wait for other threads to finish
	for t in threads:
		t.join()
	# For for child pid to finish
#	if pid > 0:
#		os.waitpid(pid, 0)