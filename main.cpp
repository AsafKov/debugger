#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

int main(int argc, char **argv) {
    if(argc < 2){
        //TODO not enough arguments?
    }
    char *function_name = argv[0];
    char *file_path = argv[1];
    char *exe_args = argv[2];
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