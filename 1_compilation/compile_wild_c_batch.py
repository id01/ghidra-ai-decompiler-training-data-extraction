from multiprocessing import Pool
import subprocess

def compile_wild_c_file(num):
	subprocess.run(["/bin/bash", "-c", "python compile_wild_c.py /secondary/torrents/wild_c/source/wildc_%s.parquet" % str(num).zfill(4)])

p = Pool(6)
#p = Pool(6)
p.map(compile_wild_c_file, range(122))
