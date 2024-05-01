#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct mappedLibrary {
    char* name;
    void* baseaddr;
    int perms;
    int shouldBeLoaded;
} mappedLibrary_t;

/* Defines for testing this file by itself */
#ifdef TEST_ENUMERATE
#ifdef DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT
#endif
#endif

/* Will return out a list of mapped libraries for the caller to process */
mappedLibrary_t** enumerateMaps(pid_t pid)
{
    int success = -1;
    FILE *fp;
    char filename[30];
    char line[850];
    long addr;
    long addrEnd;
    int garbage2;
    char str[20];
    char garbageString[255];
    char libraryString[255];
    char perms[5];
    int checkSeenLib = 0;
    int counter = 0;
    mappedLibrary_t** outputList = NULL;
    int outputListIndex = 0;
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL){
        printf("Failed to open maps\n");
        return NULL;
    }
    outputList = calloc(sizeof(mappedLibrary_t*)*2048, 1);
    
    while(fgets(line, 850, fp) != NULL)
    {
#ifdef PRINT_MEM_ANOM
        if(strstr(line, "rwx") != NULL){
            printf("RWX MEMORY REGION: %s", line);
        }
        else if(strstr(line, "r-x") != NULL && strstr(line, "/") == NULL && strstr(line, "[") == NULL){
            printf("Found R-X MEMORY NOT ON DISK: %s", line);
        }
#endif
        /* If it has a path in it, I'm just assuming its a file, and will ignore it if its not */
        if(strstr(line, "/") != NULL){
            /* addr here is the base address of the library in memory, carve this out of length X */
            sscanf(line, "%lx-%lx %s %s %s %d %s", &addr, &addrEnd, perms, garbageString, str, &garbage2, libraryString);
            DEBUG_PRINT("Its a binary\n");
            checkSeenLib = 0;
            for (counter = 0; counter < outputListIndex; counter++){
                if (strcmp(libraryString, outputList[counter]->name) == 0){
                    checkSeenLib = 1;
                    break;
                }
            }
            if (checkSeenLib == 0){
                outputList[outputListIndex] = calloc(sizeof(mappedLibrary_t), 1);
                if (outputList[outputListIndex]){
                    outputList[outputListIndex]->name = calloc(strlen(libraryString)+1, 1);
                    memcpy(outputList[outputListIndex]->name, libraryString, strlen(libraryString));
                    outputList[outputListIndex]->baseaddr = (void*)addr;
                    /* Not used yet */
                    outputList[outputListIndex]->perms = 0;
                    outputList[outputListIndex]->shouldBeLoaded = 0;
                    outputListIndex++;
                }
                DEBUG_PRINT("%s(%s): %lx\n\n", libraryString, perms, addr);
            }
            success = 1;
        }
        else{
            sscanf(line, "%lx-%lx %s %s %s %d", &addr, &addrEnd, perms, garbageString, str, &garbage2);
            DEBUG_PRINT("%s(%s): %lx\n\n", str, perms, addr);
        }
        /* If we SOMEHOW end up with more than 2048 files open in that single process, then bail*/
        if (outputListIndex == 2048){
            printf("BAILING: We somehow filled up the entire array, processing will suck\n");
            break;
        }
    }
    fclose(fp);
    return outputList;
}

#ifdef TEST_ENUMERATE
int main(int argc, char* argv[]){
    int counter = 0;
    mappedLibrary_t** outputList = NULL;
    outputList = enumerateMaps(atoi(argv[1]));
    printf("Loaded Libraries in process:\n");
    /* Example iterating over list for comparing output, and freeing */
    if (outputList){
        while(outputList[counter]){
            printf("\t-%s\n", outputList[counter]->name);
            printf("\t\t- Address: %p\n", outputList[counter]->baseaddr);
            /* Freeing the output list when done */
            free(outputList[counter]->name);
            outputList[counter]->name = NULL;
            free(outputList[counter]);
            counter++;
        }
        free(outputList);
    }
    return 0;
}
#endif
