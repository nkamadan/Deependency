import os
import r2pipe


# ls -l file_path --> user? root?


# os.system("gdb -batch -ex 'file /home/kamadan/Desktop/dynamic_link_example/libfoo.so' -ex 'disassemble foo' | grep rdtsc")

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
    #r = open_file(file_path)
    #libraries = find_shared_libs(file_path)
    haha = privilege(file_path)

if __name__ == "__main__":
    main()