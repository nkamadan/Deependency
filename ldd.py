import os
import r2pipe
import json

# ls -l file_path --> user? root?

# env LD_DEBUG=bindings ./main

# os.system("gdb -batch -ex 'file /home/kamadan/Desktop/dynamic_link_example/libfoo.so' -ex 'disassemble foo' | grep rdtsc")

# Get the list of standard library functions that include rdtsc and do not include rdtsc.
# Only show the dependent symbols if they include rdtsc. There are 100s of symbols in a binary. We need to get rid of displaying every one of them. 


standard_functions = ['localtime','asctime','clock_get_time','timespec_get','clock_gettime','system_clock::now']

def imported_symbols(radare2):
    imported_list = []
    # Analyze all
    print("Analyzing the file ###############################")
    radare2.cmd('aaa')
    isj_result = radare2.cmd("isj")
    blocksJson = json.loads(isj_result)
    for block in blocksJson:
        if (block["name"].find("imp.") > -1) and (block["flagname"].find("sym.imp") > -1):
            imported_list.append(block["realname"])
        else:
            continue
    return imported_list


def search_for_imported_symbols(binaries,file_path):
    r = open_file(file_path)
    imported_syms = imported_symbols(r)
    r_imported_symbols = []
    for bin in binaries:
        imp_sym_for_this_bin = ""
        for symbol in imported_syms:
            output = os.popen("gdb -batch -ex 'file {}' -ex 'disassemble {}'".format(bin,symbol)).read()
            if(len(output) > 0):
                imp_sym_for_this_bin += symbol
                imp_sym_for_this_bin += ";"
        r_imported_symbols.append(imp_sym_for_this_bin)
    for x in range(len(r_imported_symbols)):
        if(r_imported_symbols[x] == ""):
            r_imported_symbols[x] = "No imported symbol"
    return r_imported_symbols

def privilege(binaries):
    privileges = []
    for bin in binaries:
        result = os.popen("ls -l {}".format(bin)).read()
        splitted = result.split(" ")
        privileges.append(splitted[2])
    return privileges    

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
            if(len(elem) == 2):  # /lib64/ld-linux-x86-64.so.2 (0x00007fb438338000)
                final_paths.append(elem[0].strip())
            else:               # libfoo.so => /lib/libfoo.so (0x00007fb438310000)
                final_paths.append(elem[2].strip())

    return final_paths
    


def open_file(file_path):

    if (file_path == ''):
        file_path = input("enter the file name to be analyzed: ")

    return (r2pipe.open(file_path))


def main():
    file_path = "/home/kamadan/Desktop/dynamic_link_example/main"
    r = open_file(file_path)
    imp_list = imported_symbols(r)
    print(imp_list)
    libraries = find_shared_libs(file_path)
    print(libraries)
    result = search_for_imported_symbols(libraries,file_path)
    print("result after this line")
    print(result)
    haha = privilege(libraries)
    print(haha)

if __name__ == "__main__":
    main()
