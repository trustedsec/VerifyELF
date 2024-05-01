#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Some static paths that I noticed are used alot across linux systems */
char* libPath_static[5] = {"/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib64", "/lib64", NULL};
int libPath_static_size = 4;

/* NOTE: Set PRINT_DIFFS to actually print out all the diffs in the section you find at each offset, and BREAK_ON_FIRST_DIFF to just identify where the offset diffs */
#define PRINT_DIFFS 0
#define BREAK_ON_FIRST_DIFF 1

/* NOTE: Uncomment this to test all permissions, even read write (tons of false positives) */
//#define VALIDATE_ALL_PERMS 1

#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT
#endif

#ifdef VERBOSE
#define PRINT_MEM_ANOM 1
#define VERBOSE_PRINT printf
#else
#define VERBOSE_PRINT
#endif

/* Set versions to oldest possible */
__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");
__asm__(".symver log2f,log2f@GLIBC_2.2.5");
__asm__(".symver __isoc99_sscanf,sscanf@GLIBC_2.2.5");

/* Global variables */
char *runPathDefined[255] = {0};
int runPathCount = 0;

char* fullPathSymbolsParsed[1024] = {0};
int fullPathSymbolsParsedCounter = 0;

int currentPID = 0;

char* parsedFiles[1024] = {0};
int parsedFileCount = 0;
int nestedCount = 1;
char** library_paths = NULL;
int library_paths_size = 0;
int ptrace_worked = 0;

/* We need this because apparently ptrace PEEKTEXT can return a -1 and be successful 
 * so we need to actually check the errno it set to verify that it was successful or failed */
extern int errno;


/* Structures */

/* One of these for every relocation */
typedef struct relocationEntry{
    void* offset;
    int size;
    struct relocationEntry* next;
} relocationEntry_t;

/* Initialize one of these for every binary */
typedef struct libRelocations{
    char* name;
    struct relocationEntry* head;
    struct relocationEntry* tail;
    /* just for additional info */
    int relocationsCount;
    int sectionCount;
} libRelocations_t;

/* More Globals */
libRelocations_t* parsedFilesRelocations[1024] = {0};

/* Yeah I know its bad practice, but this is a PoC */
#include "enumerate_maps.c"

/*Needed to have the code get a string from a file and all entries are NULL deliminated */
char* fgetentry_int(char* inpath, int inlenmax, FILE* fp, unsigned char entryCharOverride){
    int entryChar = 0;
    int counter = 0;
    entryChar = fgetc(fp);
    while(entryChar!=EOF){
        if (entryChar == 0){
            break;
        }
        /* if len of string is close to the max len of inpath, break out so we can at least output that*/
        if (counter+1 >= inlenmax){
            break;
        }
        inpath[counter] = (char)entryChar;
        counter++;
        entryChar = fgetc(fp);
    }
    /* Found something so null terminating it */
    if (counter != 0){
        inpath[counter] = 0;
        return inpath;
    }
    return NULL;
}

/* Parse the remote process environment variables, and add in LD_LIBRARY_PATH to the runpath */
char** get_remote_lib_paths(int pid, int* arraySize){
    FILE *fp = NULL;
    char ld_library_string[2048] = {0};
    char procPath[255] = {0};
    char** outlist = NULL;
    char* lastpath = NULL;
    char* endpath = NULL;
    int counter = 0;

    sprintf(procPath, "/proc/%d/environ", pid);
    fp = fopen(procPath, "r");
    *arraySize = 0;

    if (fp == NULL){
        return outlist;
    }

    while(fgetentry_int(ld_library_string, 2048,  fp, 0)!=NULL){
        if (strstr(ld_library_string, "LD_LIBRARY_PATH=")!= NULL){
            /* allocate random buffer size, super large*/
            outlist = calloc(2048, sizeof(char*));
            if (outlist == NULL){
                goto errorcase;
            }
            endpath = ld_library_string+strlen("LD_LIBRARY_PATH=");
            lastpath = strchr(endpath, ':');
            counter = 0;
            while(lastpath != NULL){
                outlist[counter] = calloc((int)(lastpath-endpath)+1, 1);
                if (outlist[counter] == NULL){
                    goto errorcase;
                }
                memcpy(outlist[counter], endpath, (int)(lastpath-endpath));
                counter++;
                *arraySize = counter;
                endpath = lastpath + 1;
                lastpath = strchr(endpath, ':');
            }
        }
    }

retlab:
    fclose(fp);
    return outlist;

errorcase:
    /* Free outlist if set */
    if (outlist){
        for (counter = 0; counter < *arraySize; counter++){
            if (outlist[counter]){
                free(outlist[counter]);
                outlist[counter] = NULL;
            }
        }
        free(outlist);
    }
    arraySize = 0;
    goto retlab;
}

/* Adding the relocation to a relocation list for the file */
int addRelocation(char* libPath, void* addr, int size){
    relocationEntry_t* tempPtr = NULL;
    int counter = 0;
    for (counter = 0; counter < parsedFileCount; counter++){
        if (strcmp(libPath, parsedFilesRelocations[counter]->name) == 0){
            tempPtr = calloc(sizeof(libRelocations_t), 1);
            tempPtr->offset = addr;
            tempPtr->size = size;
            if (parsedFilesRelocations[counter]->head == NULL){
                 parsedFilesRelocations[counter]->head = tempPtr;
                 parsedFilesRelocations[counter]->tail = tempPtr;
                parsedFilesRelocations[counter]->relocationsCount++;
            }
            else{
                parsedFilesRelocations[counter]->tail->next = tempPtr;
                parsedFilesRelocations[counter]->tail = tempPtr;
                parsedFilesRelocations[counter]->relocationsCount++;
            }
            break;
        }
    }
    return 0;
}

/* NOTE: Not needed here, remove from public */
#define SIZE 256
float entropy_calc(long byte_count[], int length)
{
      float entropy = 0;
      float count = 0;
      int i = 0;

      /* entropy calculation */
      for (i = 0; i < SIZE; i++)
        {
          if (byte_count[i] != 0)
            {
              count = (float) byte_count[i] / (float) length;
              entropy += -count * log2f(count);
            }
        }
      return entropy;
}

float get_entropy(unsigned char* indata, int size){
    long byte_count[SIZE] = {0};
    int counter = 0;
    for (counter = 0; counter < size; counter++){
        byte_count[indata[counter]] += 1;
    }
    return entropy_calc(byte_count, size);
}

/* Dumb generic hash function, should be replaced with crc32 or something, 
 * or just use this and hope for the best */
uint32_t calcGenericHash(unsigned char* basePtr, int size){
    uint32_t hashCalc = 0x0;
    int counter = 0;
    for (counter = 0; counter < size; counter++){
        hashCalc = (((hashCalc + basePtr[counter])&0x00ffffff) << 8) | ((hashCalc &0xff000000) >> 24);
    }
    return hashCalc;
}

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

int ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
    int bytesRead = 0;
    int i = 0;
    long word = 0;
    long *ptr = (long *) vptr;
    int retcode = 0;
    errno = 0;
    while (bytesRead < len)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
        if(word == -1 && errno != 0)
        {
            VERBOSE_PRINT("Failed to PTRACE_PEEKTEXT, address: 0x%lX len: %d offset: %d\n", addr, len, bytesRead);
            retcode = 1;
            break;
        }
        bytesRead += sizeof(word);
        ptr[i++] = word;
    }
    return retcode;
}
/* Global base lib name list */
char gBaseLibName[255] = {0};

/* Parse out the base name from a library path */
char* getBaseLibName(char* libpath){
    char* baseLibPath = NULL;
    int basePathCounter = 0;
    memset(gBaseLibName, 0, 255);
    baseLibPath = libpath + strlen(libpath) - 1;
    while (baseLibPath[0] != '/'){
        baseLibPath--;
    }
    baseLibPath++;
    /* Should now be the last part of the library name */
    while (baseLibPath[basePathCounter] != '.' && basePathCounter < strlen(libpath)){
        basePathCounter++;
    }
    if (basePathCounter < 255){
        memcpy(gBaseLibName, baseLibPath, basePathCounter);
    }
    return gBaseLibName;
}

/* Actually validate the sections, and take a TON of arguments to do it */
int validateSections(char* libPath, int memPerms, char* actualLibPath, uint32_t eh_size, uint64_t eh_offset, uint64_t wtext_offset, uint32_t wtext_size, unsigned char* sectionBase, unsigned char* remoteSectionBase, unsigned char* staticRemoteSectionBase, int sectionSize, 
    uint64_t remoteOffset, uint64_t localOffset){
    unsigned char* localSection = NULL;
    unsigned char* remoteSection = NULL;
    uint32_t localHash = 0;
    uint32_t remoteHash = 0;
    int counter = 0;
    int ptraceCheckCode = 1;
    int useRelativeOffset = 0;
    int retcode = 0;
    int unmatchedBytesCount = 0;
    int bytesCounter = 0;
    if (sectionBase == NULL || remoteSectionBase == NULL){
        DEBUG_PRINT("%s SectionBase is %p and RemoteSectionBase: %p\n", libPath, sectionBase, remoteSectionBase);
        return 2;
    }
    DEBUG_PRINT("Validating fileOffset: %x to memOffset: %x Size: %d\n", localOffset, remoteOffset, sectionSize);
    /* First step, copy in code of sectionSize from sectionBase + localOffset into section of memory */
    localSection = calloc(sectionSize+10, 1);
    /* ptrace_read for some reason seems to be overwriting 8 bytes at the end, so trying this to compensate */
    remoteSection = calloc(sectionSize+10, 1);
    
    memcpy(localSection, sectionBase+localOffset, sectionSize);
    /* Second step, copy in memory from remote process into local memory section (remoteSectionBase + remoteOffset) */
    if (ptrace_worked != 0){
        if (remoteOffset < localOffset + 0x5000){
            DEBUG_PRINT("Its a binary that is relative offset\n");
            ptraceCheckCode = ptrace_read(currentPID, (uint64_t)(remoteSectionBase + remoteOffset), remoteSection, sectionSize);
            useRelativeOffset = 1;
        }
        else{
            DEBUG_PRINT("Assuming its a static base, so we'll see what happens\n");
            if (staticRemoteSectionBase){
                DEBUG_PRINT("remoteSectionBase: 0x%lX, staticRemoteSectionBase: 0x%lX\n", remoteSectionBase, staticRemoteSectionBase);
                DEBUG_PRINT("Doing calculation that results in 0x%lx\n", (uint64_t)(remoteSectionBase + (uint64_t)((uint64_t)remoteOffset - (uint64_t)staticRemoteSectionBase )));
                ptraceCheckCode = ptrace_read(currentPID, (uint64_t)(remoteSectionBase + (uint64_t)((uint64_t)remoteOffset - (uint64_t)staticRemoteSectionBase )), remoteSection, sectionSize);
            }
            else{
                DEBUG_PRINT("RemoteOffset: 0x%lx\n", remoteOffset);
                ptraceCheckCode = ptrace_read(currentPID, (uint64_t)(remoteSectionBase + remoteOffset), remoteSection, sectionSize);
            }
        }
    }
    /* Apply relocations to section based off relocationEntry offset + size to both, if offset of relocation is static, and remoteSectionBase + localOffset == remoteOffset  or within like 0x1000 bytes of each other just use that offset */
    
    /* Calc generic hash for both sections */
    if (ptraceCheckCode == 0){
        /* Apply relocations to each here */
        relocationEntry_t* headPtr = NULL;
        for (counter=0; counter < parsedFileCount; counter++){
            if (strstr(parsedFilesRelocations[counter]->name, libPath) != 0){
                DEBUG_PRINT("Found Library: %s\n", parsedFilesRelocations[counter]->name);
                headPtr = parsedFilesRelocations[counter]->head;
                while (headPtr){
                    /* Relative offsets */
                    if (useRelativeOffset){
                        if (((uint64_t)(headPtr->offset)) >= remoteOffset && ((uint64_t)(headPtr->offset)) < remoteOffset+sectionSize){
                            DEBUG_PRINT("Nulling out bytes at %d\n", (((uint64_t)(headPtr->offset)-remoteOffset)));
                            memset(localSection+(((uint64_t)(headPtr->offset)-remoteOffset)), 0, headPtr->size);
                            memset(remoteSection+(((uint64_t)(headPtr->offset)-remoteOffset)), 0, headPtr->size);
                        }
                    }
                    else{
                        /* Static offsets */
                        if (((uint64_t)(headPtr->offset)) >= remoteOffset && ((uint64_t)(headPtr->offset)) < remoteOffset+sectionSize){
                            DEBUG_PRINT("Nulling out bytes at %d\n", (((uint64_t)(headPtr->offset)-remoteOffset)));
                            memset(localSection+(((uint64_t)(headPtr->offset)-remoteOffset)), 0, headPtr->size);
                            memset(remoteSection+(((uint64_t)(headPtr->offset)-remoteOffset)), 0, headPtr->size);
                        }
                    }
                    headPtr = headPtr->next;
                }
            }
        }

        /* Calculate the hashes, and do the comparison */
        localHash = calcGenericHash(localSection, sectionSize);
        remoteHash = calcGenericHash(remoteSection, sectionSize);
        DEBUG_PRINT("LocalHash: %X\n", localHash);
        DEBUG_PRINT("RemoteHash: %X\n", remoteHash);
        if (localHash != remoteHash){
            for (counter = 0; counter < sectionSize; counter++){
                if (localSection[counter] != remoteSection[counter]){
                    if (unmatchedBytesCount == 0){
                        if ((eh_offset != 0) && (remoteOffset)+counter < (eh_offset)+eh_size && (remoteOffset)+counter > (eh_offset)){
                            printf("\tEH_Frame differs, Perms: 0x%x might be FP match %s vs %s: %X vs %X FileOffset: %lX\n", memPerms, libPath, actualLibPath, localHash, remoteHash, localOffset+counter);
                        }
                        else if ((wtext_offset != 0) && (remoteOffset)+counter <= (wtext_offset)+wtext_size && (remoteOffset)+counter >= (wtext_offset)){
                            printf("\tWTEXT differs(openGL?), Perms: 0x%x might be FP match %s vs %s: %X vs %X FileOffset: %lX\n", memPerms, libPath, actualLibPath, localHash, remoteHash, localOffset+counter);
                        }
                        else{
                            printf("\tSection differs, Perms: 0x%x %s vs %s: %X vs %X FileOffset: %lX MaxAddr: %lX\n", memPerms, libPath, actualLibPath, localHash, remoteHash, localOffset+counter, localOffset+sectionSize);
                        }
                        if (BREAK_ON_FIRST_DIFF == 1){
                            break;
                        }
                    }
                    unmatchedBytesCount+= 1;
                }
                else{
                    if (unmatchedBytesCount != 0){
                        if (PRINT_DIFFS != 0){
                            printf("\t\tOrigBytes: ");
                            for (bytesCounter = 1; bytesCounter <= unmatchedBytesCount; bytesCounter++){
                                printf("%02X ", localSection[(counter-bytesCounter)]);
                            }
                            printf("\n\t\tModiBytes: ");
                            for (bytesCounter = 1; bytesCounter <= unmatchedBytesCount; bytesCounter++){
                                printf("%02X ", remoteSection[(counter-bytesCounter)]);
                            }
                            printf("\n");
                        }
                        /* Reset counter */
                        unmatchedBytesCount = 0;
                    }
                }
            }
            retcode = 1;
        }
        else{
            DEBUG_PRINT("Hashes match\n");
        }
    }
    /* Cleanup, cause otherwise we would be leaking a TON of memory */
    if (localSection){
        free(localSection);
    }
    if (remoteSection){
        free(remoteSection);
    }
    /* If hashes differ, then walk the entire buffer, and identify the offset of the library that errors occure at */
    return retcode;
}

/* Display the relocations for debugging purposes, and below 
 * that free them later on with same logic */

void printRelocations(void){
    int counter = 0;
    relocationEntry_t* headPtr = NULL;
    for (counter=0; counter < parsedFileCount; counter++){
        VERBOSE_PRINT("Library: %s\n", parsedFilesRelocations[counter]->name);
        headPtr = parsedFilesRelocations[counter]->head;
        while (headPtr){
            VERBOSE_PRINT("\tOffset: %p\n", headPtr->offset);
            VERBOSE_PRINT("\tSize: %d\n", headPtr->size);
            headPtr = headPtr->next;
        }
    }
}

int freeRelocations(void){
    int counter = 0;
    int c2 = 0;
    relocationEntry_t* headPtr = NULL;
    relocationEntry_t* tempPtr = NULL;
    for (counter = 0; counter < parsedFileCount; counter++){
        headPtr = parsedFilesRelocations[counter]->head;
        while (headPtr){
            tempPtr = headPtr->next;
            free(headPtr);
            headPtr = tempPtr;
        }
        parsedFilesRelocations[counter]->head = NULL;
        parsedFilesRelocations[counter]->tail = NULL;
    }
}

/* Defining this so that we can recurivly call that function from parseElf */
int parseElfRead(int recurse, mappedLibrary_t** mapList, char* inpath, char* prevPath);

/* Actually do all the parsing of the input binary */
int parseElf(int recurse, mappedLibrary_t** mapList, unsigned char* elfdata, int size, char* prevPath){
    Elf64_Ehdr *hdr = (Elf64_Ehdr*)elfdata;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Shdr *sh_strtab;
    Elf64_Dyn * dynhdr;
    Elf64_Sym *syms;
    Elf64_Rel *relPtr;
    Elf64_Rela *relaPtr;
    
    char* strings = NULL;
    char* start = NULL;
    unsigned char* tempDbg = NULL;
    int counter = 0;
    int c2 = 0;
    int tempctr = 0;
    char libPath[255] = {0};
    int nestCheck = 2;
    int runpathCount = 0;
    int runpathExists = 0;
    int firstTimeParsed = 0;
    int checkCounter = 0;
    void* remoteBase = NULL;
    void* staticRemoteBase = NULL;
    int firstSection = 0;
    char* actualPathPtr = NULL;
    unsigned char* baseLibraryName = NULL;
    char* lastPath = NULL;
    int lastPathLocation = 0;
    int libraryPathCounter = 0;
    uint64_t eh_frame_offset = 0;
    uint32_t eh_frame_size = 0;
    uint64_t wtext_offset = 0;
    uint32_t wtext_size = 0;
    char* endpathptr = NULL;
    char* startpathptr = NULL;
    /* Verify that it is actually an elf file..... We're actually running across all binaries */
    if (elfdata[0] != 0x7f || elfdata[1] != 0x45 || elfdata[2] != 0x4c || elfdata[3] != 0x46){
        return 0;
    }
    DEBUG_PRINT("Type: %x\n", hdr->e_type);
    DEBUG_PRINT("Machine: %x\n", hdr->e_machine);
    DEBUG_PRINT("Version: %x\n", hdr->e_version);
    DEBUG_PRINT("Entry: %lx\n", hdr->e_entry);
    DEBUG_PRINT("progHdr: %lx\n", hdr->e_phoff);
    DEBUG_PRINT("shoff: %lx\n", hdr->e_shoff);
    DEBUG_PRINT("e_shnum: %x\n", hdr->e_shnum);
    DEBUG_PRINT("e_ehsize: %x\n", hdr->e_ehsize);
    phdr = (Elf64_Phdr*)(elfdata + hdr->e_phoff);
    /* Validate hashes here, actually going to re-parse after relocations are parsed out, then call validate there */
    for (counter = 0; counter < hdr->e_phnum; counter++){
        DEBUG_PRINT("Counter: %d\n", counter);
        DEBUG_PRINT("\tType: %d\n", phdr[counter].p_type);
        if (phdr[counter].p_type == 1){
            DEBUG_PRINT("\tIts Loadable\n");
            DEBUG_PRINT("\tOffset: 0x%lx\n", phdr[counter].p_offset);
            DEBUG_PRINT("\tAddress: 0x%lx\n", phdr[counter].p_paddr);
            DEBUG_PRINT("\tVirtualAddress: 0x%lx\n", phdr[counter].p_vaddr);
            DEBUG_PRINT("\tFileSize: %ld\n", phdr[counter].p_filesz);
            DEBUG_PRINT("\tMemSize: %ld\n", phdr[counter].p_memsz);
            DEBUG_PRINT("\tMemPerms: 0x%x\n", phdr[counter].p_flags);
        }
    }
    DEBUG_PRINT("=======================\n");
    shdr = (Elf64_Shdr*)(elfdata + hdr->e_shoff);
    sh_strtab = (Elf64_Shdr*)(&shdr[hdr->e_shstrndx]);
    for (counter = 0; counter < hdr->e_shnum; counter++){
        DEBUG_PRINT("---------------------------------\n");
        DEBUG_PRINT("Counter: %d\n", counter);
        DEBUG_PRINT("Type: %x\n", shdr[counter].sh_type);
        DEBUG_PRINT("Link: %x\n", shdr[counter].sh_link);
        
        syms = (Elf64_Sym*)(elfdata + shdr[counter].sh_offset);
        strings = elfdata + sh_strtab->sh_offset;
        DEBUG_PRINT("NameIndex: %X\n", shdr[counter].sh_name);
        DEBUG_PRINT("SectionName: %s\n", strings + shdr[counter].sh_name);
        if (strcmp(".eh_frame", strings + shdr[counter].sh_name) == 0){
            eh_frame_offset = shdr[counter].sh_addr;
            eh_frame_size = shdr[counter].sh_size;
        }
        if (strcmp("wtext", strings + shdr[counter].sh_name) == 0){
            wtext_offset = shdr[counter].sh_addr;
            wtext_size = shdr[counter].sh_size;
        }

        DEBUG_PRINT("Addr: 0x%lX\n", shdr[counter].sh_addr);
        
        if (shdr[counter].sh_type == SHT_RELA){
            DEBUG_PRINT("RELA Type\n");
            relaPtr = (Elf64_Rela*)(elfdata + shdr[counter].sh_offset);
            for (c2 = 0; c2 < (shdr[counter].sh_size / sizeof(Elf64_Rela)); c2++){
                void* refOffset = (void*)(relaPtr[c2].r_offset);
                (void)addRelocation(prevPath, refOffset, 8);
                DEBUG_PRINT("\tRelocation Offset: %p\n", refOffset);
                DEBUG_PRINT("\t\tAddend: %lx\n", relaPtr[c2].r_addend);
                DEBUG_PRINT("\t\tInfo: %lx\n", relaPtr[c2].r_info);
                DEBUG_PRINT("\t\tInfo Type: %lx\n", ELF64_R_TYPE(relaPtr[c2].r_info));
                DEBUG_PRINT("\t\tInfo Sym: %lx\n", ELF64_R_SYM(relaPtr[c2].r_info));
            }
        }

        if (shdr[counter].sh_type == SHT_REL){
            DEBUG_PRINT("REL Type\n");
            relPtr = (Elf64_Rel*)(elfdata + shdr[counter].sh_offset);
            for (c2 = 0; c2 < (shdr[counter].sh_size / sizeof(Elf64_Rel)); c2++){
                void* refOffset = (void*)(relPtr[c2].r_offset);
                (void)addRelocation(prevPath, refOffset, 8);
                DEBUG_PRINT("\tRelocation Offset: %p\n", refOffset);
                DEBUG_PRINT("\t\tInfo: %lx\n", relPtr[c2].r_info);
                DEBUG_PRINT("\t\tInfo Type: %lx\n", ELF64_R_TYPE(relaPtr[c2].r_info));
                DEBUG_PRINT("\t\tInfo Sym: %lx\n", ELF64_R_SYM(relaPtr[c2].r_info));
            }

        }
 
        if (shdr[counter].sh_type == SHT_DYNAMIC){
            DEBUG_PRINT("\tIts Dynamic linking info\n");
            DEBUG_PRINT("\t\tFlags: %lx\n",  shdr[counter].sh_flags);
            DEBUG_PRINT("\t\tAddr: %lx\n", shdr[counter].sh_addr);
            DEBUG_PRINT("\t\tOffset: %lx\n", shdr[counter].sh_offset);
            dynhdr = (Elf64_Dyn*)(elfdata + shdr[counter].sh_offset);
            DEBUG_PRINT("\t\tBaseAddr: %p\n", elfdata);
            DEBUG_PRINT("\t\tdynhdrAddr: %p\n", dynhdr);
            DEBUG_PRINT("\t\tsh_entsize: %lx\n", shdr[counter].sh_entsize);
            strings = elfdata + shdr[shdr[counter].sh_link].sh_offset;
            for (c2 = 0; c2 < (shdr[counter].sh_size/sizeof(Elf64_Dyn)); c2++){
                /* Handle the runpaths, cause if we don't we gets TONS of false positives */
                if (dynhdr[c2].d_tag == DT_RUNPATH || dynhdr[c2].d_tag == DT_RPATH){
                    runpathExists = 0;
                    for (runpathCount = 0; runpathCount < runPathCount; runpathCount++){
                        if (strcmp(strings + dynhdr[c2].d_un.d_ptr, runPathDefined[runpathCount]) == 0){
                            runpathExists = 1;
                            break;
                        }
                    }
                    if (runpathExists == 0){
                        VERBOSE_PRINT("RUNPATH: %s\n", strings + dynhdr[c2].d_un.d_ptr);
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
            for (c2 = 0; c2 < (shdr[counter].sh_size/sizeof(Elf64_Dyn)); c2++){
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
                    DEBUG_PRINT("\t\t\tSymName: %s\n", strings + dynhdr[c2].d_un.d_ptr);
                    /* If libdl.so is NEEDED can probably assume that it loads up 
                     * additional libraries by design */
                    if (strcmp(strings + dynhdr[c2].d_un.d_ptr, "libdl.so.2") == 0){
                        VERBOSE_PRINT("Uses DLOPEN\n");
                    }
                    if (recurse == 1){
                        nestedCount += 1;
                        /* Try runpath first if defined */
                        for (runpathCount = 0; runpathCount < runPathCount; runpathCount++){
                            memset(libPath, 0, 255);
                            sprintf(libPath, "%s/%s", runPathDefined[runpathCount], strings + dynhdr[c2].d_un.d_ptr);
                            nestCheck = parseElfRead(recurse, mapList, libPath, prevPath);
                            if (nestCheck != 2){
                                if (nestedCount > 0){
                                    VERBOSE_PRINT("Parsing from %s: %s\n", prevPath, libPath);
                                }
                                else{
                                    VERBOSE_PRINT("Parsing: %s\n", libPath);
                                }
                                break;
                            }
                        }
                        /* Check library paths from LD_LIBRARY_PATHS, then do this if set*/
                        if (library_paths && library_paths_size > 0){
                            for (libraryPathCounter = 0; libraryPathCounter < library_paths_size; libraryPathCounter++){
                                memset(libPath, 0, 255);
                                sprintf(libPath, "%s/%s", library_paths[libraryPathCounter], strings + dynhdr[c2].d_un.d_ptr);
 
                                nestCheck = parseElfRead(recurse, mapList, libPath, prevPath);
                                if (nestCheck == 0){
                                    if (nestedCount > 0){
                                        VERBOSE_PRINT("Parsing from %s: %s\n", prevPath, libPath);
                                    }
                                    else{
                                        VERBOSE_PRINT("Parsing: %s\n", libPath);
                                    }
                                }
                                if (nestCheck != 2){
                                    break;
                                }
                            }
                        }
                        if (nestCheck == 2){
                            for (libraryPathCounter = 0; libraryPathCounter < libPath_static_size; libraryPathCounter++){
                                memset(libPath, 0, 255);
                                DEBUG_PRINT("LibraryPath: %s\n", libPath_static[libraryPathCounter]);
                                DEBUG_PRINT("Library: %s\n", strings + dynhdr[c2].d_un.d_ptr);
                                sprintf(libPath, "%s/%s", libPath_static[libraryPathCounter], strings + dynhdr[c2].d_un.d_ptr);
                                nestCheck = parseElfRead(recurse, mapList, libPath, prevPath);
                                if (nestCheck == 0){
                                    if (nestedCount > 0){
                                        VERBOSE_PRINT("Parsing from %s: %s\n", prevPath, libPath);
                                    }
                                    else{
                                        VERBOSE_PRINT("Parsing: %s\n", libPath);
                                    }
                                    if (nestCheck != 2){
                                        break;
                                    }
                                }

                            }
                        }
                        nestedCount -= 1;
                    }
                }
                else{
                    DEBUG_PRINT("Its an address, skipping\n");
                }
            }
        }

        firstTimeParsed = 0;
        for (checkCounter = 0; checkCounter < fullPathSymbolsParsedCounter; checkCounter++){
            if (strcmp(prevPath, fullPathSymbolsParsed[checkCounter]) == 0){
                firstTimeParsed = 1;
            }
        }
        if (shdr[counter].sh_type == SHT_DYNSYM && firstTimeParsed == 0){
            if (fullPathSymbolsParsedCounter < 1024){
                fullPathSymbolsParsed[fullPathSymbolsParsedCounter] = calloc(strlen(prevPath)+1, 1);
                if (fullPathSymbolsParsed[fullPathSymbolsParsedCounter]){
                    memcpy(fullPathSymbolsParsed[fullPathSymbolsParsedCounter], prevPath, strlen(prevPath));
                }
                fullPathSymbolsParsedCounter+=1;
            }
            DEBUG_PRINT("\tIts DynSym\n");
            syms = (Elf64_Sym*)(elfdata + shdr[counter].sh_offset);
            strings = elfdata + shdr[shdr[counter].sh_link].sh_offset;
        }
    }
    /* If mapList is set we then actually do the validation */
    if (mapList != NULL){
        staticRemoteBase = NULL;
        /* Actually validate the sections here */
        for (counter = 0; counter < hdr->e_phnum; counter++){
            DEBUG_PRINT("Counter: %d\n", counter);
            DEBUG_PRINT("\tType: %d\n", phdr[counter].p_type);
            if (phdr[counter].p_type == 1){
                DEBUG_PRINT("\tIts Loadable, validating hashes\n");
                DEBUG_PRINT("\tOffset: 0x%lx\n", phdr[counter].p_offset);
                DEBUG_PRINT("\tAddress: 0x%lx\n", phdr[counter].p_paddr);
                DEBUG_PRINT("\tVirtualAddress: 0x%lx\n", phdr[counter].p_vaddr);
                DEBUG_PRINT("\tFileSize: %ld\n", phdr[counter].p_filesz);
                DEBUG_PRINT("\tMemSize: %ld\n", phdr[counter].p_memsz);
                DEBUG_PRINT("\tMemPerms: 0x%x\n", phdr[counter].p_flags);
                if (firstSection == 0){
                    staticRemoteBase = (void*)(phdr[counter].p_vaddr& 0xFFFFFFFFFFFFF000);
                    DEBUG_PRINT("Setting staticRemoteBase: %lX\n", staticRemoteBase);
                    firstSection+=1;
                }
                remoteBase = NULL;
                baseLibraryName = getBaseLibName(prevPath);
                if (mapList){
                    c2 = 0;
                    lastPathLocation = strlen(baseLibraryName);
                    /* See if its a library (with .so) */
                    /* If not then do base application, may need to add third option to look for stuff ending with - after the library name */
 
                    if (remoteBase == 0){
                        c2 = 0;
                        baseLibraryName[lastPathLocation] = 0;
                        DEBUG_PRINT("Getting BasePath for %s its %s\n", prevPath, baseLibraryName);
                        while (mapList[c2]){
                            lastPath = mapList[c2]->name + strlen(mapList[c2]->name) - 1;
                            while (lastPath[0] != '/'){
                                lastPath--;
                            }
                            lastPath++;
                            /* Actually do strcmp because the path shouldn't change for the binary itself */
                            if (strcmp(lastPath, baseLibraryName) == 0){
                                DEBUG_PRINT("Found library base, setting: %s:%p\n", mapList[c2]->name, mapList[c2]->baseaddr);
                                remoteBase = mapList[c2]->baseaddr;
                                break;
                            }
                            c2++;
                        }
                    }
                   
                    if (remoteBase == 0){
                        c2 = 0;
                        baseLibraryName[lastPathLocation] = '.';
                        DEBUG_PRINT("Getting BasePath for %s its %s\n", prevPath, baseLibraryName);
                        while (mapList[c2]){
                            lastPath = mapList[c2]->name + strlen(mapList[c2]->name) - 1;
                            while (lastPath[0] != '/'){
                                lastPath--;
                            }
                            lastPath++;
                            if (strstr(mapList[c2]->name, baseLibraryName) != NULL){
                                DEBUG_PRINT("Found library base, setting: %s:%p\n", mapList[c2]->name, mapList[c2]->baseaddr);
                                remoteBase = mapList[c2]->baseaddr;
                                break;
                            }
                            c2++;
                        }
                    }

                    if (remoteBase == 0){
                        c2 = 0;
                        baseLibraryName[lastPathLocation] = '-';
                        DEBUG_PRINT("Getting BasePath for %s its %s\n", prevPath, baseLibraryName);
                        while (mapList[c2]){
                            lastPath = mapList[c2]->name + strlen(mapList[c2]->name) - 1;
                            while (lastPath[0] != '/'){
                                lastPath--;
                            }
                            lastPath++;
                            if (strstr(mapList[c2]->name, baseLibraryName) != NULL){
                                DEBUG_PRINT("Found library base, setting: %s:%p\n", mapList[c2]->name, mapList[c2]->baseaddr);
                                remoteBase = mapList[c2]->baseaddr;
                                break;
                            }
                            c2++;
                        }
                    }
                }

                actualPathPtr = NULL;
                if (remoteBase){
                    actualPathPtr = mapList[c2]->name;
                }

                /* NOTE: validating all permissions means validate RW sections too, which obviously causes 
                 * a ton of false positives, leaving it in as a flag incase you want to  though*/
#ifndef VALIDATE_ALL_PERMS
                if (phdr[counter].p_flags == 1 || phdr[counter].p_flags == 4 || phdr[counter].p_flags == 5){
#endif
                    if ( validateSections(baseLibraryName, phdr[counter].p_flags, actualPathPtr, eh_frame_size, eh_frame_offset, wtext_offset, wtext_size, elfdata, remoteBase, staticRemoteBase, phdr[counter].p_filesz, phdr[counter].p_paddr, phdr[counter].p_offset) == 1){
                        DEBUG_PRINT("SECTION DIFFERS!!!!!!\n");
                    }
#ifndef VALIDATE_ALL_PERMS
                }
#endif
            }
        }
    }

    return 0;
}

/* Wrap the parseElf function by reading in the file, setting up all structures 
 * and lists we need, and then calling the original */

int parseElfRead(int recurse, mappedLibrary_t** mapList, char* inpath, char* prevPath){
    unsigned char* buf = NULL;
    int size = 0;
    FILE* elf = NULL;
    int checkcount = 0;
    int found = 0;
    for (checkcount = 0; checkcount < parsedFileCount; checkcount++){
        if (strcmp(inpath, parsedFiles[checkcount]) == 0){
            found = 1;
        }
    }
    if (found == 1){
        return 1;
    }
    elf = fopen(inpath, "rb");
    if (elf == NULL){
        return 2;
    }
    /* Allocate and save off file name */
    parsedFiles[parsedFileCount] = calloc(strlen(inpath)+1, 1);
    /* Actually initialize the structure too */
    parsedFilesRelocations[parsedFileCount] = calloc(sizeof(libRelocations_t), 1);
    /* Just account for failures */
    if (parsedFiles[parsedFileCount] == NULL || parsedFilesRelocations[parsedFileCount] == NULL){
        return 3;
    }
    parsedFilesRelocations[parsedFileCount]->name = calloc(strlen(inpath)+1, 1);
    if (parsedFilesRelocations[parsedFileCount]->name == NULL){
        return 4;
    }
    memcpy(parsedFiles[parsedFileCount], inpath, strlen(inpath));
    memcpy(parsedFilesRelocations[parsedFileCount]->name, inpath, strlen(inpath));
    parsedFileCount+=1;
    fseek(elf, 0, SEEK_END);
    size = ftell(elf);
    fseek(elf, 0, SEEK_SET);
    buf = calloc(size+1, 1);
    if (buf == NULL){
        return 1;
    }
    memset(buf, 0, size);
    (void)fread(buf, 1, size, elf);
    parseElf(recurse, mapList, buf, size, inpath);
    free(buf);
    fclose(elf);
    return 0;
}

int processPID(int inPID){
    int counter = 0;
    int c2 = 0;
    char* baseLibPath = NULL;
    int basePathCounter = 0;
    char basePath[255] = {0};
    char binaryPath[255] = {0};
    char procPath[255] = {0};
    int procPID = 0;
    currentPID = inPID;
    mappedLibrary_t** outputList = NULL;
    /* Figure out the file that started the process */
    procPID = inPID;
    sprintf(procPath, "/proc/%d/exe", procPID);
    printf("Reading link to %s\n", procPath);
    if (readlink(procPath, binaryPath, 255) < 0){
        return 1;
    }
    printf("BinaryPath: %s\n", binaryPath);
    ptrace_worked = 0;
    if (strncmp("/snap/", binaryPath, 6)!=0 && ptrace_attach(procPID) == 0){
        ptrace_worked = 1;
    }
    else{
        printf("Failed ptrace_attach, skipping section verification\n");
    }
    library_paths_size = 0;
    library_paths = NULL;
    library_paths = get_remote_lib_paths(procPID, &library_paths_size);
    /* Actually call enumerateMaps to get actually loaded modules */
    outputList = enumerateMaps(procPID);

    /* Add first runPath that could be used (local directory of binary) */
    runPathDefined[runPathCount] = calloc(strlen(binaryPath)+1, 1);
    sprintf(runPathDefined[runPathCount], "%s", binaryPath);
    counter = strlen(binaryPath);
    while (runPathDefined[runPathCount][counter] != '/'){
        counter--;
    }
    runPathDefined[runPathCount][counter] = 0;
    VERBOSE_PRINT("RUNPATH: %s\n", runPathDefined[runPathCount]);
    runPathCount++;

    /* Actually parse the ELF file recursively to identify all dependencies */
    parseElfRead(1, outputList, binaryPath, NULL);
    if (ptrace_worked == 1){
        ptrace_detach(procPID);
    }
    /* Print loaded parsed files, these will get cleaned up at the end */
    VERBOSE_PRINT("\n\n");
    if (parsedFileCount == 1){
        printf("NOTE: This binary seems to be a static binary\n");
    }
    /* Print out the required libraries when running in verbose */
    VERBOSE_PRINT("Parsed libraries\n");
    for (counter = 0; counter < parsedFileCount; counter++){
        VERBOSE_PRINT("\t- %s\n", parsedFiles[counter]);

        /* Parse out to get only the base path, symlinks everywhere make it difficult to actually identify which libraries are used */
        baseLibPath = parsedFiles[counter] + strlen(parsedFiles[counter]) - 1;
        /* Null out the basePath, and then find the last / in it */
        memset(basePath, 0, 255);
        while (baseLibPath[0] != '/'){
            baseLibPath--;
        }
        /* Increment one to get the last part */
        baseLibPath++;
        /* Find the first . in the path, if it is there, else just put the file name as base path */
        basePathCounter = 0;
        while (baseLibPath[basePathCounter] != '.' && basePathCounter <strlen(baseLibPath) ){
            basePathCounter++;
        }
        memcpy(basePath, baseLibPath, basePathCounter);

        /* Validate that the path is in the actually mapped list, and mark it as required */
        if (outputList){
            c2 = 0;
            while(outputList[c2]){
                if (strstr(outputList[c2]->name, basePath) != NULL){
                    outputList[c2]->shouldBeLoaded = 1;
                }
                c2++;
            }
        }
    }
    /* Used for formatting */
    VERBOSE_PRINT("\n\n");

    /* Enumerate mapped list, print if the shared object wasn't actually seen when parsing
     * also clean up the allocated structs */
    if (outputList){
        VERBOSE_PRINT("Loaded but aren't explicitly loaded:\n");
        counter = 0;
        while(outputList[counter]){
            if (outputList[counter]->shouldBeLoaded == 0){
                VERBOSE_PRINT("\t-%s\n", outputList[counter]->name);
                VERBOSE_PRINT("\t\t- Address: %p\n", outputList[counter]->baseaddr);
            }
            /* Freeing the output list when done */
            free(outputList[counter]->name);
            outputList[counter]->name = NULL;
            free(outputList[counter]);
            counter++;
        }
        free(outputList);
    }
    /* Free library paths */
    if (library_paths){
        for (counter = 0; counter < library_paths_size; counter++){
            if (library_paths[counter]){
                free(library_paths[counter]);
            }
        }
        free(library_paths);
    }

    VERBOSE_PRINT("Finished, check output for information\n");

    /* Free everything else */
    freeRelocations();

    /* Free the parsed files */
    for (counter = 0; counter < parsedFileCount; counter++){
        if (parsedFilesRelocations[counter]){
            if (parsedFilesRelocations[counter]->name){
                free(parsedFilesRelocations[counter]->name);
            }
            free(parsedFilesRelocations[counter]);
        }
        free(parsedFiles[counter]);
        parsedFiles[counter] = NULL;
    }
    /* Cleanup the defined run paths */
    for (counter = 0; counter < runPathCount; counter++){
        if (runPathDefined[counter]){
            free(runPathDefined[counter]);
            runPathDefined[counter] = NULL;
        }
    }

    runPathCount = 0;
    parsedFileCount = 0;
    return 0;
}


int main(int argc, char* argv[]){
    struct dirent *procDirs = NULL;
    DIR* directory = NULL;
    int pid = 0;
    int counter = 0;
    if (argc < 2){
        printf("%s [PID|all|bin] [/path/if/using/bin]\n", argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "all") == 0){
        directory = opendir("/proc/");
        if (directory){
            while ((procDirs = readdir(directory)) != NULL){
                if (procDirs->d_type != DT_DIR){
                    continue;
                }
                pid = atoi(procDirs->d_name);
                (void)processPID(pid);
                printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            }
            closedir(directory);
        }
    }
    else if (strcmp(argv[1], "bin") == 0){
        VERBOSE_PRINT("BinaryPath: %s\n", argv[2]);
        runPathDefined[runPathCount] = calloc(strlen(argv[2])+1, 1);
        sprintf(runPathDefined[runPathCount], "%s", argv[2]);
        counter = strlen(argv[2]);
        while (runPathDefined[runPathCount][counter] != '/'){
            counter--;
        }
        runPathDefined[runPathCount][counter] = 0;
        VERBOSE_PRINT("RUNPATH: %s\n", runPathDefined[runPathCount]);
        runPathCount++;

        parseElfRead(1, NULL, argv[2], NULL);
        VERBOSE_PRINT("Parsed libraries\n");
        for (counter = 0; counter < parsedFileCount; counter++){
            VERBOSE_PRINT("\t- %s\n", parsedFiles[counter]);
        }
        VERBOSE_PRINT("\n\nLoaded but aren't explicitly loaded:\nFinished, check output for information\n");
        printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    }
    else{
        (void)processPID(atoi(argv[1]));
        printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    }
    /* Free all the temp saved off files parsed, if we hit 1024 bail */
    for (counter = 0; counter < fullPathSymbolsParsedCounter; counter++){
        if (fullPathSymbolsParsed[counter]){
            free(fullPathSymbolsParsed[counter]);
            fullPathSymbolsParsed[counter] = NULL;
        }
    }
    fullPathSymbolsParsedCounter = 0;
    return 0;
}
