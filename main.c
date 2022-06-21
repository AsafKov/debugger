#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "elf64.h"
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

bool isElf(char *file_path);

bool isExecutable(char *file_path);

bool getFunctionInfo(char *file_path, char *func_name, bool *isGlobal, bool *is_dynamic, unsigned long* func_address, unsigned long* got_offset);

void debug(int pid, unsigned long func_address, bool is_dynamic, unsigned long got_offset);

static int counter = 0;

int main(int argc, char **argv) {
    if (argc < 2) {
        //TODO not enough arguments?
    }
    char *function_name = argv[0];
    char *file_path = argv[1];
    char *exe_args = argv[2];
    unsigned long func_address;
    unsigned long got_offset;
    bool is_global = false;
    bool is_dynamic = false;

    if (!isElf(file_path) || !isExecutable(file_path)) {
        printf("PRF:: %s not an executable!\n", function_name);
        return 0;
    }

    if (!getFunctionInfo(file_path, function_name, &is_global, &is_dynamic, &func_address, &got_offset)) {
        printf("PRF:: %s not found!\n", function_name);
        return 0;
    }

    if (!is_global) {
        printf("PRF:: %s is not a global symbol! :(!\n", function_name);
        return 0;
    }

    int pid = fork();
    if(pid == -1){
        // TODO: fork error
    }
    if(pid == 0){
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            // TODO: ptrace error
        }
        execl(file_path, exe_args, NULL);
    } else {
        debug(pid, func_address, is_dynamic, got_offset);
    }
}

void debug(int pid, unsigned long func_address, bool is_dynamic, unsigned long got_offset){
    unsigned long func_instruction, func_break_point, return_addr_instruction, return_break_point, plt_instruction, plt_breakpoint;
    int wait_status;
    struct user_regs_struct regs;
    waitpid(pid, &wait_status, 0);

    if(is_dynamic){
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        plt_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.rip + got_offset, NULL);
    }

    func_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) func_address, NULL);
    func_break_point = (func_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, pid, (void*)func_address, (void*)func_break_point);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&wait_status);

    while(WIFSTOPPED(wait_status)) {
        counter++;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return_addr_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.rsp, NULL);
        return_break_point = (return_addr_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, (void*)return_addr_instruction, (void*)return_break_point);
        if(regs.rip == func_address + 1){
            ptrace(PTRACE_POKETEXT, pid, (void*)func_address, (void*)func_instruction);
            regs.rip--;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);
        /** Print return value **/

        func_break_point = (func_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, (void*)func_address, (void*)func_break_point);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);
    }
}

bool isElf(char *file_path) {
    FILE *file = fopen(file_path, "r");
    char *initial_bytes = (char *) malloc(sizeof(char) * 5);

    fread(initial_bytes, 1, 4, file);
    initial_bytes[4] = '\0';

    bool is_elf = strcmp(initial_bytes, "_ELF") == 0;
    free(initial_bytes);
    fclose(file);
    return is_elf;
}

bool isExecutable(char *file_path) {
    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        //TODO bad file
    }

    void *elf = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *) elf;

    return elf_header->e_type == 2;
}

bool getFunctionInfo(char *file_path, char *func_name, bool *isGlobal, bool *is_dynamic, unsigned long* func_address, unsigned long* got_offset) {
    int fd;
    bool is_executable = false;
    unsigned long symbol_entries = 0, realoc_entries = 0;
    char *string_table, *str_tab, *dyn_str, *curr_name, *section_name;
    Elf64_Sym *dynamic_symbols, *realoc_table, *sym_tab;
    Elf64_Shdr *section_header_arr, string_section;
    Elf64_Ehdr *elf_header;
    void *elf;

    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        //TODO bad file
    }

    elf = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    elf_header = (Elf64_Ehdr *) elf;
    section_header_arr = (Elf64_Shdr *) ((char *) elf + elf_header->e_shoff); //getting sectionHeader
    string_section = section_header_arr[elf_header->e_shstrndx]; //getting string section
    string_table = (char *) elf + string_section.sh_offset; //getting the string table
    Elf64_Half numOfSections = elf_header->e_shnum;

    for (int i = 0; i < numOfSections; i++) {
        section_name = section_header_arr[i].sh_name + string_table;
        if (section_header_arr[i].sh_type == 2 && strcmp(section_name, ".symtab") == 0) {
            symbol_entries = section_header_arr[i].sh_size /
                              section_header_arr[i].sh_entsize; //size of section : size of each entry
            sym_tab = (Elf64_Sym *) ((char *) elf + section_header_arr[i].sh_offset);
        }
        if (section_header_arr[i].sh_type == 3 && strcmp(section_name, ".strtab") == 0) {
            if ((char *) elf + section_header_arr[i].sh_offset != string_table)
                str_tab = ((char *) elf + section_header_arr[i].sh_offset); //getting the string table of the symbol table
        }
        if (section_header_arr[i].sh_type == 3 && strcmp(section_name, ".dynstr") == 0) {
            if ((char *) elf + section_header_arr[i].sh_offset != string_table)
                dyn_str = ((char *) elf + section_header_arr[i].sh_offset); //getting the string table of the symbol table
        }
        if (section_header_arr[i].sh_type == 4 && strcmp(section_name, ".rela.plt") == 0) {
            realoc_entries = section_header_arr[i].sh_size /
                                      section_header_arr[i].sh_entsize; //size of section : size of each entry
            realoc_table = (Elf64_Sym *) ((char *) elf + section_header_arr[i].sh_offset);
        }
        if (section_header_arr[i].sh_type == 11 && strcmp(section_name, ".dynsym") == 0) {
            dynamic_symbols = (Elf64_Sym *) ((char *) elf + section_header_arr[i].sh_offset);
        }
    }

    for (int i = 0; i < symbol_entries; i++) {
        curr_name = str_tab + sym_tab[i].st_name; //the current symbol name in the string table of symbol table
        if (!strcmp(curr_name, func_name)) {
            if (ELF64_ST_BIND(sym_tab[i].st_info) == 1) {
                if(sym_tab[i].st_shndx == 0){
                    *is_dynamic = true;
                }
                *func_address = sym_tab[i].st_value;
                *isGlobal = true;
            }
            is_executable = true;
        }
    }

    if(is_dynamic){
        for(int i=0; i < realoc_entries; i++){
            int entryIndex = ELF64_R_SYM(realoc_table[i].st_info);
            curr_name = dyn_str + dynamic_symbols[entryIndex].st_name;
            if(strcmp(curr_name, func_name) == 0){
                *got_offset = dynamic_symbols[i].st_value; // Offset to GOT entry of func
                break;
            }
        }
    }

    close(fd);
    return is_executable;
}