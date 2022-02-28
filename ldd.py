import os
import r2pipe
import json
from dataclasses import dataclass



# ls -l file_path --> user? root?

# env LD_DEBUG=bindings ./main

# os.system("gdb -batch -ex 'file /home/kamadan/Desktop/dynamic_link_example/libfoo.so' -ex 'disassemble foo' | grep rdtsc")

# Get the list of standard library functions that include rdtsc and do not include rdtsc.
# Only show the dependent symbols if they include rdtsc. There are 100s of symbols in a binary. We need to get rid of displaying every one of them. 


all_symbols = [] # list of elements including addr + name data 
shared_libs = [] # list of libs that the binary we analyze needs

@dataclass
class symbols_meta:
    addr: str
    name: str # symbols imported from this lib
    instr_count: int # # of instructions this symbol has

    def __init__(self, addr: str = "init", name: str = "init",instr_count: int = -1):
        self.name = name
        self.addr = addr
        self.instr_count = instr_count

    def __str__(self): 
        return "Symbol object-> Name: %s, Adress: %s, Instr: %s" % (self.name,self.addr,self.instr_count)

@dataclass
class lib_symbols:
    lib: str
    symbols: list # symbols imported from this lib --> list of symbols_meta [symbols_meta]
    priv: str # user or root privilege
    def __init__(self, lib: str = "init", symbols: list = [], priv: str = "init"):
        self.lib = lib
        self.symbols = symbols
        self.priv = priv

    def __str__(self): 
        return "Lib object-> Name: %s, Symbols: %s, Privilege: %s" % (self.lib,self.symbols,self.priv)

standard_functions = ['localtime','asctime','clock_get_time','timespec_get','clock_gettime','system_clock::now']

def clean_symbols():
    a = 5

def imported_symbols(radare2):
    # Analyze all
    print("Analyzing the file ###############################")
    radare2.cmd('aaa')
    isj_result = radare2.cmd("isj")
    blocksJson = json.loads(isj_result)
    for block in blocksJson:
        if (block["name"].find("imp.") > -1) and (block["flagname"].find("sym.imp") > -1 and block["vaddr"] != 0):
            temp_symbol = symbols_meta(block["vaddr"],block["realname"])
            all_symbols.append(temp_symbol)
        else:
            continue
    return all_symbols


def populate_libs_wsymbols():
    for symbol in all_symbols:
        for bin in shared_libs:
            output = os.popen("gdb -batch -ex 'file {}' -ex 'disassemble {}'".format(bin.lib,symbol.name)).read()
            temp = []
            incr = 0
            for out in output:
                if out == "\n":
                    incr = incr + 1
            #print("COUNT: {} and symbol {}".format(incr, symbol.name))
            if(len(output) > 0):
                symbol.instr_count = incr
                if(len(bin.symbols) == 0):
                    temp.append(symbol)
                    bin.symbols = temp
                    break
                else:
                    bin.symbols.append(symbol)
                    break
    return shared_libs

def populate_libs_wsymbols_reverse():
    for bin in shared_libs:
        for symbol in all_symbols:
            output = os.popen("gdb -batch -ex 'file {}' -ex 'disassemble {}'".format(bin.lib,symbol.name)).read()
            temp = []
            incr = 0
            for out in output:
                if out == "\n":
                    incr = incr + 1
            #print("COUNT: {} and symbol {}".format(incr, symbol.name))
            if(len(output) > 0):
                symbol.instr_count = incr - 2 # incr contains 2 more information lines.
                if(len(bin.symbols) == 0):
                    temp.append(symbol)
                    bin.symbols = temp
                else:
                    bin.symbols.append(symbol)
    return shared_libs
 

def privilege():
    for bin in shared_libs:
        result = os.popen("ls -l {}".format(bin.lib)).read()
        splitted = result.split(" ")
        bin.priv = splitted[2]
    return shared_libs   

def does_this_function_in_this_binary_contain_rdtsc(func,lib):
    a = 5

def find_shared_libs(binary):
    result = os.popen("ldd {}".format(binary)).read()
    dependencies = result.split("\n")
    clean = []
    for dep in dependencies:
        clean.append(dep.split(" "))
    final_paths = []
    for elem in clean:
        if(elem[0]==""):
            clean.remove(elem)
        elif (elem[0].find("linux-vdso") != -1):
            #print("vdso --> ignored")
            continue
        else:
            lib = lib_symbols()
            if(len(elem) == 2):  # /lib64/ld-linux-x86-64.so.2 (0x00007fb438338000)
                lib.lib = elem[0].strip()
                shared_libs.append(lib)
            else:   
                lib.lib = elem[2].strip()            # libfoo.so => /lib/libfoo.so (0x00007fb438310000)
                shared_libs.append(lib)

    return shared_libs 


def open_file(file_path):

    if (file_path == ''):
        file_path = input("enter the file name to be analyzed: ")

    return (r2pipe.open(file_path))


def main():
    file_path = "/home/kamadan/Desktop/dynamic_link_example/main"
    #file_path = "/bin/ls"
    r = open_file(file_path)
    imp_list = imported_symbols(r)
    #print(imp_list)
    libraries = find_shared_libs(file_path)
    #print(libraries)
    result = populate_libs_wsymbols()
    #print(result)
    # print("global variables")
    # print(all_symbols)
    # print(shared_libs)
    last = privilege()
    print(last)

if __name__ == "__main__":
    main()
