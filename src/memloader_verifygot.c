#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include "debug.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

/* Set the version of the symbols to the oldest we can get so that 
 * we can hopefully run the binary on more systems than just the latest */
__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");
__asm__(".symver log2f,log2f@GLIBC_2.2.5");
__asm__(".symver __isoc99_sscanf,sscanf@GLIBC_2.2.5");

/* Symbols to ignore since some are in the vdso when ld resolves them, and others are common local symbols */
char* ignoreSymbols[] = {"time", "gettimeofday", "getcpu", "clock_gettime", "_ITM_deregisterTMCloneTable", "__gmon_start__", "_ITM_registerTMCloneTable", "__tls_get_addr", "__libc_stack_end"};
int ignoreSymbolsCount = 9;

/* Not best practice, but hey it works */
#include "enumerate_maps.c"

#ifdef VERBOSE
#define PRINT_VERBOSE printf
#else
#define PRINT_VERBOSE
#endif

/*Defines to map Elf_Phdr to Elf32_Phdr and whatnot incase I want to port to 32bit one day*/
#if UINTPTR_MAX == 0xffffffff
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Shdr    Elf32_Shdr
#define Elf_Dyn Elf32_Dyn
#define ELF_R_TYPE(i)   ((i) & 0xff)
#define ELF_R_SYM(x)    ((x) >> 8)
#define SHT_REL_TYPE    SHT_REL
#define X86
#else
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rela
#define Elf_Shdr Elf64_Shdr
#define Elf_Dyn Elf64_Dyn
#define ELF_R_TYPE(i)   ((i) & 0xffffffff)
#define ELF_R_SYM(x)    ((x) >> 32)
#define SHT_REL_TYPE    SHT_RELA
#endif

/* Global variables */
int initialized = 0;

void* startupFunc = NULL;
void* soEntry = NULL;
void* loaderBase = NULL;
int loaderBaseSize = 0;

char *runPathDefined[255] = {0};
int runPathCount = 0;

mappedLibrary_t** mappingArray = NULL;

uint64_t got_offset = 0;
int got_size = 0;

/* Symbol management structures and functions */

typedef struct symbolEntry {
    char* Name;
    uint64_t offset;
    struct symbolEntry* next;
} symbolEntry_t;

typedef struct symbolsStruct{
    int entries;
    symbolEntry_t* head;
    symbolEntry_t* tail;
} symbolsStruct_t;

symbolsStruct_t symbolsList = {0};

void addSymbolValue(const char* name, uint64_t offset){
    symbolEntry_t* temp = NULL;
    symbolEntry_t* tempptr = NULL;
    tempptr = symbolsList.tail;
    temp = calloc(sizeof(symbolEntry_t)+1, 1);
    if (temp == NULL){
        return;
    }
    if (strlen(name) == 0){
        free(temp);
        return;
    }
    
    temp->Name = calloc(strlen(name)+1, 1);
    memcpy(temp->Name, name, strlen(name));
    temp->offset = offset;
    if (tempptr == NULL){
        /* First entry */
        symbolsList.head = temp;
        symbolsList.tail = temp;
    }
    else{
        tempptr->next = temp;
        symbolsList.tail = temp;
    }
    symbolsList.entries+=1;
}

char* getSymbolValue(uint64_t offset){
    symbolEntry_t* temp = symbolsList.head;
    char* outname = NULL;
    while (temp != NULL){
        if (temp->offset == offset){
            outname = temp->Name;
            break;
        }
        temp = temp->next;
    }
    return outname;
}

void freeSymbols(void){
    symbolEntry_t* temp = symbolsList.head;
    symbolEntry_t* temp2 = NULL;
    while (temp != NULL){
        temp2 = temp->next;
        if (temp->Name){
            free(temp->Name);
            temp->Name = NULL;
        }
        free(temp);
        temp = temp2;
    }
}

/* Parse the binary for LOAD commands and guess the size 
 * (adding padding incase we aren't quite right) */

unsigned int
get_binary_full_size(Elf_Ehdr *header)
{
    Elf_Phdr *segments = NULL;
    int i = 0;
    unsigned int size = 0;

    /* Validate header is in fact not NULL ptr */
    if (header){
        segments = (Elf_Phdr*)(((unsigned char*)header) + header->e_phoff);
    }
    /* If either header was NULL or segments is NULL then bail */
    if (segments == NULL){
        return 0;
    }
    
    /* Iterate over headers */
    for(i = 0; i < header->e_phnum; i++)
    {
        if(segments[i].p_type == PT_LOAD)
        {
            /* Just add the p_memsz up cause it isn't crazy critical that we be 
             * 100% right with the page size we need, just need enough for these sections */
            size += segments[i].p_memsz;
        }
    }
    /* Add in some padding since I'm probably not accounting for everything
     * and we're just going to be freeing it when done anyway */
    size += 0x20000;
    return size;
}

/* Globals for the library management stuffs */

void* *libHandles = NULL;
void* *libHandleBase = NULL;
char* *libHandleNames = NULL;
int libHandleCounter = 0;
int skippedLibwrap = 0;
int skipLibWrap = 1;
char libwrapName[255] = {0};

void loadLibraryName(char* name){
    struct link_map *lm = NULL;
    char basePath[255] = {0};
    char testpath[255] = {0};
    int runpathCounter = 0;
    if (initialized == 0){
        libHandles = calloc(sizeof(void*), 256);
        libHandleBase = calloc(sizeof(void*), 256);
        libHandleNames = calloc(sizeof(void*), 256);
        initialized = 1;
        loadLibraryName("libc.so.6");
        loadLibraryName("libdl.so.2");
    }
    if (skipLibWrap == 1 && strstr(name, "libwrap") != NULL){
        DEBUG_PRINT("Not loading libwrap\n");
        skippedLibwrap = 1;
        memcpy(libwrapName, name, strlen(name));
        return;
    }
    if (libHandles){
        libHandles[libHandleCounter] = dlopen(name, RTLD_NOW);
        if (libHandles[libHandleCounter] == NULL){
            for (runpathCounter = 0; runpathCounter < runPathCount; runpathCounter++){
                sprintf(basePath, "%s/%%s", runPathDefined[runpathCounter]);
                sprintf(testpath, basePath, name);
                PRINT_VERBOSE("Trying to open: %s\n", testpath);
                libHandles[libHandleCounter] = dlopen(testpath, RTLD_NOW);
                if (libHandles[libHandleCounter]){
                    break;
                }
            }
        }
        if (libHandles[libHandleCounter]){
            PRINT_VERBOSE("Loaded: %s\n", name);
            lm = (struct link_map*)libHandles[libHandleCounter];
            libHandleBase[libHandleCounter] =(void*)( lm->l_addr);
            libHandleNames[libHandleCounter] = calloc(strlen(name)+1, 1);
            if (libHandleNames[libHandleCounter]){
                memcpy(libHandleNames[libHandleCounter], name, strlen(name));
            }
            libHandleCounter+=1;
        }
    }
}

void freeLibraries(void){
    int counter = 0;
    if (libHandleNames && libHandles && libHandleBase){
        for (counter = 0; counter < libHandleCounter; counter++){
            if (libHandleNames[counter]){
                free(libHandleNames[counter]);
                libHandleNames[counter] = NULL;
            }
            if (libHandles[counter]){
                dlclose(libHandles[counter]);
            }
        }
        free(libHandles);
        free(libHandleNames);
        free(libHandleBase);
    }
}

void *resolve(const char* sym)
{
    int counter = 0;
    void* output = NULL;
    unsigned char* outputTest = NULL;
    int c2 = 0;
    char basePath[255] = {0};
    int basePathcount = 0;
    int tryAgain = 0;
    uint64_t checkOffset = 0;
    uint64_t libSize = 0;
    
    /* We'll be looping over all the libraries we dlopen'ed, and then resolve the 
     * symbol and return that address in the remote process space */
    for(counter = 0; counter < libHandleCounter; counter++){
        tryAgain = 0;
        if (libHandles[counter] != NULL){
            /* NOTE: Need to figure out a way to GUARANTEE that the function dlsym 
             * returns is the one that ld would have used, right now it does OK, but not perfect 
             * also need to deal with symbol versions..... */
            output = dlsym(libHandles[counter], sym);
            if (output){
                outputTest = output;
                DEBUG_PRINT("First 4 bytes of symbol: %02X %02X %02X %02X\n", outputTest[0], outputTest[1], outputTest[2], outputTest[3]);
                PRINT_VERBOSE("Symbol %s found in %s getting base from mappedList\n", sym, libHandleNames[counter]);
                memset(basePath, 0, 255);
                memcpy(basePath, libHandleNames[counter], strlen(libHandleNames[counter]));
                basePathcount = 0;
                while(basePath[basePathcount] != '.'){
                    basePathcount += 1;
                }
                basePath[basePathcount] = '.';
                basePath[basePathcount+1] = 0;
                c2 = 0;
                while(mappingArray[c2]){
                    if (strstr(mappingArray[c2]->name, basePath) != NULL){
                        if ((int64_t)(((unsigned char*)(output))-((uint64_t)libHandleBase[counter])) < 0){
                            output = NULL;
                            tryAgain = 1;
                            break;
                        }
                        else{
                            checkOffset = (uint64_t)(((unsigned char*)(output))-((uint64_t)libHandleBase[counter]));
                            /* Get the full size of the library, and if the offset falls outside it then try again cause its the wrong one */
                            libSize = get_binary_full_size(libHandleBase[counter]);
                            if (checkOffset < libSize){
                                PRINT_VERBOSE("RemoteBaseName: %s LocalBase: %p BaseAddress: %p ResolvedLocal: %p\n", mappingArray[c2]->name, libHandleBase[counter], mappingArray[c2]->baseaddr, output);
                                PRINT_VERBOSE("Offset in library: %lx\n", (uint64_t)(((unsigned char*)(output))-((uint64_t)libHandleBase[counter])));
                                output = (void*)((unsigned char*)(output)-(uint64_t)libHandleBase[counter])+(uint64_t)(mappingArray[c2]->baseaddr);
                                break;
                            }
                            else {
                                output = NULL;
                                tryAgain = 1;
                            }
                        }
                    }
                    c2++;
                }
                if (tryAgain != 1){
                    break;
                }
            }
        }
    }
    DEBUG_PRINT("SymbolName %s at %p\n", sym, output);
    return output;
}

/* This is wher things get weird, we're essentially loading the binary into our 
 * process, execept we're using the remote processes memory space */

void relocate(Elf_Shdr* shdr, const Elf_Sym* syms, const char* strings, const char* src, char* dst, uint64_t remoteBaseAddress, uint64_t compensateBaseAddr)
{
    Elf_Rel* rel = (Elf_Rel*)(src + shdr->sh_offset);
    int j;
    #ifdef X86
    Elf32_Word *ref = 0;
    #else
    void* *ref = 0;
    #endif
    if (syms == NULL){
        return;
    }
    DEBUG_PRINT("Trying reallocation\n");
    for(j = 0; j < shdr->sh_size / sizeof(Elf_Rel); j += 1) {
        const char* sym = strings + syms[ELF_R_SYM(rel[j].r_info)].st_name;
        #ifdef X86
        ref = (Elf32_Word*)(dst + (rel[j].r_offset-compensateBaseAddr));
        #else
        ref = (void*)(dst + (rel[j].r_offset-compensateBaseAddr));
        #endif
        DEBUG_PRINT("Symbol %s Type : %d offset: %lX\n", sym, ELF_R_TYPE(rel[j].r_info), rel[j].r_offset);
        addSymbolValue(sym, rel[j].r_offset);
        switch(ELF_R_TYPE(rel[j].r_info)) {
            #ifdef X86
            case R_386_32:
                *ref += syms[ELF_R_SYM(rel[j].r_info)].st_value;
                break;
            case R_386_PC32:
                *ref += (Elf32_Word)(syms[ELF_R_SYM(rel[j].r_info)].st_value - (uint32_t)ref + remoteBaseAddress);
                break;
            case R_386_JMP_SLOT:
                *ref = (Elf32_Word)resolve(sym);
                if (*ref == 0){
                    *ref = (Elf32_Word)(remoteBaseAddress + syms[ELF_R_SYM(rel[j].r_info)].st_value);
                }
                break;
            case R_386_GLOB_DAT:
                *ref = (Elf32_Word)(remoteBaseAddress+ syms[ELF_R_SYM(rel[j].r_info)].st_value);
                break;
            case R_386_RELATIVE:
                DEBUG_PRINT("Relative stuff\n");
                *ref += (Elf32_Word)remoteBaseAddress;
                break;
            #else
            case R_X86_64_64:
                DEBUG_PRINT("R_X86_64_64\n");
                *ref = (void*)(remoteBaseAddress+ syms[ELF_R_SYM(rel[j].r_info)].st_value + rel[j].r_addend);
                break;
            case R_X86_64_JUMP_SLOT:
                DEBUG_PRINT("JUMP_SLOT\n");
                *ref = (void*)resolve(sym);
                if (*ref == NULL){
                    *ref = (void*)(remoteBaseAddress+ syms[ELF_R_SYM(rel[j].r_info)].st_value);
                    PRINT_VERBOSE("Symbol: %s at 0x%lX\n", sym, remoteBaseAddress + syms[ELF_R_SYM(rel[j].r_info)].st_value);
                }
                else{
                    PRINT_VERBOSE("Symbol: %s at 0x%lX %p\n", sym, rel[j].r_offset, *ref);
                }
                break;
            case R_X86_64_GLOB_DAT:
                DEBUG_PRINT("Trying to load GLOB_DAT\n");
                *ref = (void*)resolve(sym);
                if (*ref == NULL){
                    *ref = (void*)(remoteBaseAddress + syms[ELF_R_SYM(rel[j].r_info)].st_value);
                    PRINT_VERBOSE("Symbol: %s at 0x%lX %p (NULL)\n", sym, rel[j].r_offset, *ref);
                }
                else{
                    PRINT_VERBOSE("Symbol: %s at 0x%lX %p\n", sym, rel[j].r_offset, *ref);
                }
                break;
            case R_X86_64_RELATIVE:
                DEBUG_PRINT("Relative stuff\n");
                *ref = (void*)(remoteBaseAddress+ rel[j].r_addend);
                break;
            #endif
            default:
                DEBUG_PRINT("Not working right : %d\n", ELF_R_TYPE(rel[j].r_info));
                break;
        }
    }
}

void *elf_load (char *elf_start, unsigned int size, uint64_t remoteBaseAddress, char**retBaseAddressSections, unsigned int* mappedSize)
{
    Elf_Ehdr *hdr     = NULL;
    Elf_Phdr *phdr    = NULL;
    Elf_Shdr *shdr    = NULL;
    Elf_Sym  *syms    = NULL;
    Elf_Shdr *sh_strtab;
    Elf_Dyn * dynhdr;
    char *strings = NULL;
    char *globalStrings = NULL;
    char *start   = NULL;
    char *baseAddressSections = NULL;
    char *taddr   = NULL;
    int baseAddressSectionsCounter = 0;
    int i = 0;
    int reallocCount = 0;
    unsigned int memsize = 0;
    unsigned char* tempDbg = NULL;
    char *exec = NULL;
    int c2 = 0;
    int tempctr = 0;
    int runpathExists = 0;
    char* endpathptr = NULL;
    char* startpathptr = NULL;
    int runpathCount = 0;

    DEBUG_PRINT("Trying to load elf\n");

    hdr = (Elf_Ehdr *) elf_start;

    /* Checking if elf image is valid, not checking arch matches although we REALLY should....*/
    if (elf_start[0] != 0x7f || elf_start[1] != 0x45 || elf_start[2] != 0x4c || elf_start[3] != 0x46){
        return NULL;
    }


    memsize = get_binary_full_size(hdr);
    exec = mmap(NULL, memsize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(!exec) {
        DEBUG_PRINT("MMAP error\n");
        return 0;
    }
    *mappedSize = memsize;
    loaderBase = exec;
    loaderBaseSize = memsize;
    DEBUG_PRINT("Mapped %x to %x\n", exec, exec+size+0x1000000);
    
    /* Null out the memory */
    memset(exec,0x0,memsize);

    phdr = (Elf_Phdr *)(elf_start + hdr->e_phoff);
    
    DEBUG_PRINT("Starting to load\n");
    DEBUG_PRINT("Going through e_phnum ->%d\n", hdr->e_phnum);
    DEBUG_PRINT("e_shnum %x\n", hdr->e_shnum);
    DEBUG_PRINT("e_ehsize %x\n", hdr->e_ehsize);
    shdr = (Elf64_Shdr*)(elf_start + hdr->e_shoff);
    sh_strtab = (Elf64_Shdr*)(&shdr[hdr->e_shstrndx]);
    strings = elf_start+ sh_strtab->sh_offset;
    globalStrings = elf_start+ sh_strtab->sh_offset;
    for(i=0; i < hdr->e_shnum; ++i) {
        if (baseAddressSectionsCounter == 1){
            baseAddressSections = (char*)(shdr[i].sh_addr &0xFFFFFFFFFFFFF000);
            *retBaseAddressSections = baseAddressSections;
        }
        baseAddressSectionsCounter++;

        if (strcmp(".got", globalStrings + shdr[i].sh_name) == 0){
            PRINT_VERBOSE("Found .got\n");
            PRINT_VERBOSE("Address offset is : %lX\n", shdr[i].sh_addr);
            got_offset = shdr[i].sh_addr;
            got_size = shdr[i].sh_size;
        }
        if (shdr[i].sh_type == SHT_DYNAMIC) {
            dynhdr = (Elf64_Dyn*)(elf_start+ shdr[i].sh_offset);
            strings = elf_start+ shdr[shdr[i].sh_link].sh_offset;
            DEBUG_PRINT("Doing DYNAMIC info\n");

            for (c2 = 0; c2 < (shdr[i].sh_size/sizeof(Elf64_Dyn)); c2++){
                DEBUG_PRINT("\t\t\tCounter: %d\n", c2);
                DEBUG_PRINT("\t\t\tDynHdr Offset: %p\n\t\t\t\t", &dynhdr[c2]);
                tempDbg = (unsigned char*)&dynhdr[c2];
                DEBUG_PRINT("\t\t\tSymType: %lx\n", dynhdr[c2].d_tag);
                DEBUG_PRINT("\t\t\tSymVal: %lx\n", dynhdr[c2].d_un.d_val);

                if (dynhdr[c2].d_tag == DT_RUNPATH || dynhdr[c2].d_tag == DT_RPATH){
                    PRINT_VERBOSE("RUNPATH NEEDED: %s\n", strings + dynhdr[c2].d_un.d_ptr);

                    runpathExists = 0;
                    for (runpathCount = 0; runpathCount < runPathCount; runpathCount++){
                        if (strcmp(strings + dynhdr[c2].d_un.d_ptr, runPathDefined[runpathCount]) == 0){
                            runpathExists = 1;
                            break;
                        }
                    }
                    if (runpathExists == 0){
                        DEBUG_PRINT("RUNPATH: %s\n", strings + dynhdr[c2].d_un.d_ptr);
                        runPathDefined[runPathCount] = calloc(strlen(strings + dynhdr[c2].d_un.d_ptr)+1, 1);
                        sprintf(runPathDefined[runPathCount], "%s", strings + dynhdr[c2].d_un.d_ptr);
                        if (strchr(runPathDefined[runPathCount], ':')){
                            DEBUG_PRINT("Multiple paths defined, adding all\n");
                            startpathptr = runPathDefined[runPathCount];
                            endpathptr = strchr(startpathptr, ':');
                            while(endpathptr){
                                runPathCount+=1;
                                runPathDefined[runPathCount] = calloc((int)(endpathptr-startpathptr)+1, 1);
                                if (runPathDefined[runPathCount]){
                                    memcpy(runPathDefined[runPathCount], startpathptr, (int)(endpathptr-startpathptr));
                                }
                                DEBUG_PRINT("RunPathAdded: %s\n", runPathDefined[runPathCount]);
                                startpathptr = endpathptr + 1;
                                endpathptr = strchr(startpathptr, ':');
                            }
                            runPathCount+=1;
                            runPathDefined[runPathCount] = calloc(strlen(startpathptr)+1, 1);
                            if (runPathDefined[runPathCount]){
                                memcpy(runPathDefined[runPathCount], startpathptr, strlen(startpathptr));
                            }
                        }
                        runPathCount++;
                    }
                }
            }

            for (c2 = 0; c2 < (shdr[i].sh_size/sizeof(Elf64_Dyn)); c2++){
                DEBUG_PRINT("\t\t\tCounter: %d\n", c2);
                DEBUG_PRINT("\t\t\tDynHdr Offset: %p\n\t\t\t\t", &dynhdr[c2]);
                tempDbg = (unsigned char*)&dynhdr[c2];
                DEBUG_PRINT("tempDbg: %p\n", tempDbg);
                for (tempctr = 0; tempctr < 8; tempctr++){
                    DEBUG_PRINT("%X", tempDbg[tempctr]);
                }
                DEBUG_PRINT("\n");
                DEBUG_PRINT("\t\t\tSymType: %lx\n", dynhdr[c2].d_tag);
                DEBUG_PRINT("\t\t\tSymVal: %lx\n", dynhdr[c2].d_un.d_val);
                if (dynhdr[c2].d_tag == DT_NEEDED){
                    PRINT_VERBOSE("NEEDED: %s\n", strings + dynhdr[c2].d_un.d_ptr);
                    loadLibraryName(strings + dynhdr[c2].d_un.d_ptr);
                }
            }
        }
    }
    
    for(i=0; i < hdr->e_phnum; ++i) {
            DEBUG_PRINT("%d\n", i);
            if(phdr[i].p_type != PT_LOAD) {
                    continue;
            }
            if(phdr[i].p_filesz > phdr[i].p_memsz) {
                    DEBUG_PRINT("Filesize of section greater than memsize, bailing\n");
                    munmap(exec, memsize);
                    return 0;
            }
            if(!phdr[i].p_filesz) {
                    continue;
            }
            reallocCount++;
            DEBUG_PRINT("do stuff with section\n");
            DEBUG_PRINT("P_off is %x\n", phdr[i].p_offset);
            DEBUG_PRINT("p_filesz is %x\n", phdr->p_filesz);
            DEBUG_PRINT("p_memsz is %x\n", phdr->p_memsz);
            DEBUG_PRINT("p_vaddr is %x\n", phdr->p_vaddr);
            DEBUG_PRINT("p_memsz is %x\n", phdr->p_memsz);
            DEBUG_PRINT("p_paddr is %x\n", phdr->p_paddr);
            if (baseAddressSections != NULL){
                PRINT_VERBOSE("Static base?: %p\n", baseAddressSections);
                start = elf_start + (phdr[i].p_offset- (uint64_t)baseAddressSections);
                taddr = (phdr[i].p_vaddr-(uint64_t)baseAddressSections) + exec;
                PRINT_VERBOSE("Actual Base: %p Compensated addr: %p\n", elf_start, start);
            }
            else{
                start = elf_start + phdr[i].p_offset;
                taddr = phdr[i].p_vaddr + exec;
            }
            DEBUG_PRINT("Moving memory from %x, to %x\n", start, taddr);
            /* NOTE: This could crash if the p_vaddr is a static base address, but actually gets relocated */
            memmove(taddr,start,phdr[i].p_filesz);
    }

    shdr = (Elf_Shdr *)(elf_start + hdr->e_shoff);

    /* Walk the sections and get the syms/strings value so we can do relocations later */
    DEBUG_PRINT("Loading SHT_DYNSYM\n");
    for(i=0; i < hdr->e_shnum; ++i) {
        DEBUG_PRINT("type is %x\n", shdr[i].sh_type);
        if (shdr[i].sh_type == SHT_DYNAMIC){
            DEBUG_PRINT("Type is Dynamic\n");
        }
        if (shdr[i].sh_type == SHT_DYNSYM) {
            syms = (Elf_Sym*)(elf_start + shdr[i].sh_offset);
            strings = elf_start + shdr[shdr[i].sh_link].sh_offset;
            break;
        }
    }
    /* If we skipped loading libwrap, then finally load libwrap before relocating */
    if (skippedLibwrap){
        skipLibWrap = 0;
        loadLibraryName(libwrapName);
    }
    DEBUG_PRINT("Loading SHT_REL\n");
    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_REL_TYPE) {
            DEBUG_PRINT("Trying to load SHT_REL_TYPE\n");
            relocate(shdr + i, syms, strings, elf_start, exec, remoteBaseAddress, (uint64_t)baseAddressSections);
        }
    }
    return exec;

}
/* End elf_load*/

int ptrace_attach(pid_t target)
{
    int waitpidstatus;
    int retcode = 0;

    if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
    {
        retcode = 1;
    }

    if(waitpid(target, &waitpidstatus, WUNTRACED) != target)
    {
        retcode = 2;
    }
    return retcode;
}


void ptrace_detach(pid_t target)
{   
    
    if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1)
    {
        exit(1);
    }
}

/* Gross crash handler making sure we don't segfault, and not detach */
extern int errno;
int ptrace_worked = 0;
int globalPID = 0;
void crash_handler(int dummy){
    printf("SIGSEGV, exiting gracefully\n");
    if (ptrace_worked != 0 && globalPID != 0){
        ptrace_detach(globalPID);
    }
    exit(0);
}

int ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
    int bytesRead = 0;
    int i = 0;
    long word = 0;
    long *ptr = (long *) vptr;
    int retcode = 0;
    errno = 0;
    DEBUG_PRINT("Trying to read data for %d at offset 0x%lX\n", pid, addr);
    while (bytesRead < len)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
        if(word == -1 && errno != 0)
        {
            PRINT_VERBOSE("Failed to PTRACE_PEEKTEXT, address: 0x%lX len: %d offset: %d\n", addr, len, bytesRead);
            retcode = 1;
            break;
        }
        bytesRead += sizeof(word);
        ptr[i++] = word;
    }
    return retcode;
}


int main(int argc, char** argv, char** envp)
{
    uint8_t* ptr = NULL;
    int readinsize = 0;
    char* buf = NULL;
    int size = 0;
    int pid = 0; 
    int c2 = 0;
    FILE* elf = NULL;
    char binaryPath[255] = {0};
    char procPath[255] = {0};
    uint64_t remoteBaseAddress = 0;
    uint8_t *remoteGotBytes = NULL;
    int ptraceCheckCode = 0;
    int diffCounter = 0;
    int difftemp = 0;
    unsigned int mappedSize = 0;
    char* retBaseAddressSections = NULL;
    char* symbolName = NULL;
    int ignoreCounter = 0;

    signal(SIGSEGV, crash_handler);
    pid = atoi(argv[1]);
    globalPID = pid;
    sprintf(procPath, "/proc/%d/exe", pid);
    if (readlink(procPath, binaryPath, 255) < 0){
        return 0;
    }
    if (strstr(binaryPath, "/snap/")){
        printf("Skipping snap app\n");
        return 0;
    }
    if (ptrace_attach(pid) == 0){
        ptrace_worked = 1;
    }
    mappingArray = enumerateMaps(pid);
    elf = fopen(binaryPath, "rb");
    printf("Reading in %s(%d)\n", binaryPath, pid);
    if (elf == NULL){
        printf("ERROR: Can't open file, skipping\n");
        ptrace_detach(pid);
        return 0;
    }
    fseek(elf, 0, SEEK_END);
    size = ftell(elf);
    fseek(elf, 0, SEEK_SET);
    buf = calloc(size, 1);
    if (buf == NULL){
        printf("ERROR, can't allocate memory\n");
        return 0;
    }
    readinsize = fread(buf, 1, size, elf);
    fclose(elf);
    DEBUG_PRINT("Readin %x of %x\n", readinsize, size);
    while(mappingArray[c2]){
        if (strcmp(mappingArray[c2]->name, binaryPath) == 0){
            printf("Found base binary\n");
            remoteBaseAddress = (uint64_t)(mappingArray[c2]->baseaddr); 
            break;
        }
        c2++;
    }

    ptr=elf_load(buf, size, remoteBaseAddress, &retBaseAddressSections, &mappedSize);
    /* Verify here */
    /* Find offset for .got, and then pull from mappingArray of the base executable (binaryPath), and read that offset, and verify offsets */
    if (got_offset != 0 && ptr != NULL){
        printf("Validate\n");
        remoteGotBytes = calloc(got_size+1, 1);
        if (remoteGotBytes){
            ptraceCheckCode = ptrace_read(pid, remoteBaseAddress+(got_offset-(uint64_t)retBaseAddressSections), remoteGotBytes, got_size);
            if (ptraceCheckCode == 0){
                printf("Comparing GOTs\n");
                for (c2 = 0; c2 < got_size; c2+=8){
                    if (memcmp(remoteGotBytes+ c2, ptr +got_offset+c2, 8) != 0 && memcmp(remoteGotBytes+c2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0){
                        symbolName = getSymbolValue(got_offset+c2);
                        int skipPrint = 0;
                        if (symbolName == NULL){
                            printf("Differs offset: 0x%lx: (UNKNOWN: FP?)\nLegit :", got_offset+c2);
                        }
                        else{
                            for (ignoreCounter = 0; ignoreCounter< ignoreSymbolsCount; ignoreCounter++){
                                if (strcmp(ignoreSymbols[ignoreCounter], symbolName) == 0){
                                    skipPrint = 1;
                                    break;
                                }
                            }
                            if (skipPrint == 0){
                                printf("Differs offset: 0x%lx: (%s)\nLegit :", got_offset+c2, symbolName);
                            }
                        }
                        if (skipPrint == 0){
                            for (difftemp = 0; difftemp < 8; difftemp++){
                                printf("%02X ", ptr[got_offset+c2+difftemp]);
                            }
                            printf("\nRemote:");
                            for (difftemp = 0; difftemp < 8; difftemp++){
                                printf("%02X ", remoteGotBytes[c2 +difftemp]);
                            }
                            printf("\n");
                        }
                    }
                    else{
                        diffCounter = 0;
                    }
                }
            }
            free(remoteGotBytes);
        }
        munmap(ptr, mappedSize);
    }
    ptrace_detach(pid);
    freeSymbols();
    freeLibraries();
    free(buf);
    if (mappingArray){
        for (c2 = 0; c2 < 2048; c2++){
            if (mappingArray[c2] == NULL){
                break;
            }
            if (mappingArray[c2]->name){
                free(mappingArray[c2]->name);
            }
            free(mappingArray[c2]);
        }
        free(mappingArray);
    }
    printf("Done comparing GOTs\n");
    return 0;
}
