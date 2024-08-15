from ghidra.program.model.listing import Program

options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
options.setBoolean('DWARF', False)
options.setBoolean('DWARF Line Number', False)
