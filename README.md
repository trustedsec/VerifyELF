# Verify Elf

This is a repository of a set of PoC (Proof of Concept) elf parsing and validation 
programs. The goal is simply to validate that there are no hooks installed into the 
running processes, and if there are to print out that there is and what offset the 
first difference is, or print out all differences.

## Binaries/Scripts
There are 3 source files:
- `memloader_verifygot.c`
    - This is the code that will identify GOT hooks, its seperate simply because to do this properly I need to load all the libraries of the remote process into mine, and fully load the binary inside my own process, resolve the symbols, identify the offset from the loaded base, and then calculate the remote library location based off the library at its base address.
- `parseELF_validate_sections.c`
    - This is the code that will validate all sections in a remote running process. This will identify hooks installed at function prologues or hollowed out shared objects.
- `enumerate_maps.c`
    - This is a single function and structure used to just parse /proc/<pid>/maps and return all libraries loaded and permissions.


## Usage
To run over your system, you need to build and run these as root.

### Building
```
make
```

### Verify Sections
To validate all sections of every process, you can run 
```
cd ./bins/
./parseELF_validate_sections.out all > /tmp/outputfile.txt
```
then grep for lines with "differ" in it. Note this uses 100% of 1 cpu core.

### Verify GOT Entries
This one will find things like the xz-utils backdoor. You can run it on a single process with 

```
cd ./bins/
python3 hook_scan_wrapper.py -p PID
<OR>
./memloader_test.out PID
Parsing input file, all entries should be verified
Bytes are the addresses, convert to little endian when verifying:

Differs offset: 0xe03f8:  (accept)                      <------ Example of true positive 
        Legit :10 74 32 81 FE 70 00 00 
        Remote:9B 3A D1 81 FE 70 00 00 
```

or run it over all processes (could have lots of results, will want to save to output file.

```
cd ./bins/
python3 hook_scan_wrapper.py > /tmp/outputfile.txt
<analyze manually here>
```

## Identifying Common False Positives vs True Positives
Some of the common false positives examples are going to be here.

### Example of True Positive (XZ-Utils backdoor)
```
python3 hook_scan_wrapper.py <SSHD_PID>
Differs offset: 0x108208:  (RSA_public_decrypt)
        Legit :40 82 92 BA 7B 7F 00 00
        Remote:90 7A 3F BA 7B 7F 00 00
```

### Remote GOT has all or almost all 00's
This can be caused by either loading later on, or being an internal symbol only. 
Or it doesn't reslove properly.
```
Differs offset: 0x113fc0:  (__stop_SYSTEMD_STATIC_DESTRUCT)
        Legit :00 A0 CE FE E3 5A 00 00
        Remote:00 00 00 00 00 00 00 00                  <----- Note the NULLs here

Differs offset: 0x631ff0:  (stderr)
        Legit :46 02 00 00 77 00 00 00
        Remote:48 26 63 00 00 00 00 00
```

### Resolving symbols from wrong library or wrong symbol version 
Symbol versions can explain some differences, brave does it for log/log2/pow, can manually 
verify by looking up the address of each, and then `objdump -x <libraryPath>|grep <symbolName>` 
and seeing if theres multiple versions.

```
Differs offset: 0x318d20:  (g_array_set_clear_func)
        Legit :10 2A 9F 9B AF 73 00 00                  <----- 
        Remote:10 FA 84 9B AF 73 00 00                  <-----
Differs offset: 0x3193e0:  (g_array_remove_range)
        Legit :00 2D 9F 9B AF 73 00 00
        Remote:00 FD 84 9B AF 73 00 00
Differs offset: 0x319448:  (g_array_remove_index)
        Legit :80 2A 9F 9B AF 73 00 00
        Remote:80 FA 84 9B AF 73 00 00
Differs offset: 0x3197c0:  (g_array_get_element_size)
        Legit :40 2A 9F 9B AF 73 00 00
        Remote:40 FA 84 9B AF 73 00 00
Differs offset: 0x319cc0:  (g_array_remove_index_fast)
        Legit :C0 2B 9F 9B AF 73 00 00
        Remote:C0 FB 84 9B AF 73 00 00
```

### Symbol didn't try to resolve and relocation didn't apply properly
```
Differs offset: 0x3f90:  ()                         <--- Note the missing name in ()
        Legit :00 50 71 72 6C 5A 00 00
        Remote:D0 FA 5B 7D 63 7D 00 00
```


## Things to Note
These programs have some false positives, I tried to reduce them down or make them 
easier to identify based off the output

- wtext sections in opengl: nvidia *SEEM* to overwrite these wtext sections, so these I highlight as false positives.
- GOT hooks: Some processes use RUNPATH/RPATH to load up shared objects, I try to handle these the best I can, but if I can't load the shared object its possible these end up NULL and will show as differences.
- GOT hooks: Some libraries export symbols that are duplicates to the legit one we want to load, and the way I'm loading with dlopen/dlsym don't resolve it the same way that ld does, so sometimes there will be false postives there.
