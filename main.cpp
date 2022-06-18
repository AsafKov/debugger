#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>


bool isElf(char *file_path);
bool isExecutable(char *file_path);
bool isFuncExistorGlobal (char *file_path, char* funcName, bool* isGlobal);

int main(int argc, char **argv) {
    if(argc < 2){
        //TODO not enough arguments?
    }
    char *function_name = argv[0];
    char *file_path = argv[1];
    char *exe_args = argv[2];

    if (!isElf(file_path) || !isExecutable(file_path))
    {
        printf("PRF:: %s not an executable!\n", function_name);
        return 0;
    }

    bool* isGlobal;
    *isGlobal = false;
    if (!isFuncExistorGlobal(file_path, function_name, isGlobal))
    {
        printf("PRF:: %s not found!\n", function_name);
        return 0;
    }

    if(!isGlobal)
    {
        printf("PRF:: %s is not a global symbol! :(!\n", function_name);
        return 0;
    }


}

bool isElf(char *file_path){
    FILE *file = fopen(file_path, "r");
    char *initial_bytes = (char *)malloc(sizeof(char) * 5);

    fread(initial_bytes, 1, 4, file);
    initial_bytes[4] = '\0';

    bool is_elf = strcmp(initial_bytes, "_ELF") == 0;
    free(initial_bytes);
    fclose(file);
    return is_elf;
}

bool isExecutable(char *file_path){
    int fd = open(file_path, O_RDONLY);
    if(fd == -1){
        //TODO bad file
    }

    void *elf = mmap(nullptr, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    auto* elf_header = (Elf64_Ehdr*)elf;

    return elf_header->e_type == ET_EXEC;
}

bool isFuncExistorGlobal (char *file_path, char* funcName, bool* isGlobal)
{
    int fd = open(file_path, O_RDONLY);
    if(fd == -1){
        //TODO bad file
    }
    void *elf = mmap(nullptr, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    auto* elf_header = (Elf64_Ehdr*)elf;
    Elf64_Shdr* section_header_arr = (Elf64_Shdr*)((char*)elf + elf_header->e_shoff); //getting sectionHeader
    Elf64_Shdr string_section = section_header_arr[elf_header->e_shstrndx]; //getting string section
    char *string_table = (char*)elf + string_section.sh_offset; //getting the string table
    Elf64_Half numOfSections = elf_header->e_shnum;
    Elf64_Sym *symtab;
    char *strtab;
    int numOfSymbols=0, count=0;
    for(int i = 0; i < numOfSections; i++) {
        char* nameOfSection =section_header_arr[i].sh_name + string_table; //getting the beginning of the string table + offset of current section
        if(section_header_arr[i].sh_type == 2 || !strcmp(".symtab", nameOfSection)){
            symtab = (Elf64_Sym*)((char*)elf + section_header_arr[i].sh_offset);
            numOfSymbols = section_header_arr[i].sh_size / section_header_arr[i].sh_entsize; //size of section : size of each entry
        }
        else if( section_header_arr[i].sh_type == 3 || !strcmp(".strtab", nameOfSection)){
            if((char*)elf + section_header_arr[i].sh_offset != string_table)
                strtab = ((char*)elf + section_header_arr[i].sh_offset); //getting the string table of the symbol table
        }
    }
    for(int i = 0; i < numOfSymbols; i++){
        char* currentName = strtab + symtab[i].st_name; //the current symbol name in the string table of symbol table
        if(!strcmp(currentName, funcName)) {
            if(ELF64_ST_BIND(symtab[i].st_info) == 1) {
                *isGlobal=true;
                return true;
            }
            else {
                return true;
            }
        }
    }

return false;


}