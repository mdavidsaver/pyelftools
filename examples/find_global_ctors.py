"""Find code inlined into, or called from, global constructors/destructors
"""
from __future__ import print_function

import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

ctor_dtor_names = set([
    # GCC special symbols for C++ global constructor/destructor
    #  by looking for this we're jumping through two levels of indirection.
    #   1. the .init_array and .rela.init_array sections reference the *_GLOBAL__* symbols
    #   2. each *_GLOBAL__* symbol calls a *static_initialization_and_destruction*
    # elftools can traverse #1, but not #2
    '_Z41__static_initialization_and_destruction_0ii',
])

def process_file(filename):
    #print("# in", filename)
    with open(filename, 'rb') as F:
        ELF = ELFFile(F)

        symbol_tables = [s for s in ELF.iter_sections()
                         if isinstance(s, SymbolTableSection)]

        ctor_symbols = []

        for section in symbol_tables:
            for nsym, symbol in enumerate(section.iter_symbols()):
                if symbol.name in ctor_dtor_names:
                    if symbol['st_info']['type'] != 'STT_FUNC':
                        #print(symbol.name, "## Not really ctor/dtor?")
                        return
                    start = symbol['st_value']
                    end = start + symbol['st_size']
                    if start>=end:
                        return # empty
                    #print('## Found ctor/dtor %s @ [%x:%x)'%(symbol.name, start, end))
                    ctor_symbols.append((symbol, start, end))

        # find source lines inlined in ctor/dtor
        dwarfinfo = ELF.get_dwarf_info()

        outlines = set()

        for CU in dwarfinfo.iter_CUs():
            lineprog = dwarfinfo.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None or entry.state.end_sequence:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address < entry.state.address:
                    for symbol, start, end in ctor_symbols:
                        if start <= prevstate.address and prevstate.address < end:
                            srcfilename = lineprog['file_entry'][prevstate.file - 1].name
                            line = prevstate.line
                            outlines.add('line %s:%d'%(srcfilename, line))
                prevstate = entry.state

        # find calls from ctor/dtor
        for section in ELF.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            symtable = ELF.get_section(section['sh_link'])

            for rel in section.iter_relocations():
                addr = rel['r_offset']
                for _symbol, start, end in ctor_symbols:
                    if addr < start or addr >= end:
                        continue
                    symbol = symtable.get_symbol(rel['r_info_sym'])
                    if not symbol.name:
                        continue
                    outlines.add('call %s'%(symbol.name,))

        outlines = list(outlines)
        outlines.sort()

        for line in outlines:
            print(filename, line)

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        process_file(filename)
