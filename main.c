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

bool getFunctionInfo(char *file_path, char *func_name, bool *isGlobal, bool *is_dynamic, unsigned long *func_address,
                     unsigned long *got_offset);

void debug(int pid, unsigned long func_address, bool is_dynamic, unsigned long got_offset);

void print_run(unsigned long run_number, int return_value);

int main(int argc, char **argv) {
    if (argc < 2) {
        //TODO not enough arguments?
    }
    char *function_name = argv[1];
    char *file_path = argv[2];
    unsigned long func_address;
    unsigned long got_offset;
    bool is_global = false;
    bool is_dynamic = false;

    if (!isElf(file_path) || !isExecutable(file_path)) {
        printf("PRF:: %s not an executable!\n", file_path);
        return 0;
    }

    if (!getFunctionInfo(file_path, function_name, &is_global, &is_dynamic, &func_address, &got_offset)) {
        printf("PRF:: %s not found!\n", function_name);
        return 0;
    }

    if (!is_global) {
        printf("PRF:: %s is not a global symbol! :(\n", function_name);
        return 0;
    }

    int pid = fork();
    if (pid == -1) {
        // TODO: fork error
    }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            // TODO: ptrace error
        }
        execv(file_path, argv + 2);
    } else {
        debug(pid, func_address, is_dynamic, got_offset);
    }
}

void print_run(unsigned long run_number, int return_value) {
    printf("PRF:: run #%lu returned with %d\n", run_number, return_value);
}

void debug(int pid, unsigned long func_address, bool is_dynamic, unsigned long got_offset) {
    unsigned long func_instruction, func_break_point, return_addr_instruction, return_break_point, plt_instruction, plt_breakpoint;
    unsigned long orig_stack_ptr;
    unsigned long entry_counter = 0;
    bool orig_reached = false;
    Elf64_Addr return_address, plt_address;
    int wait_status, value;
    struct user_regs_struct regs;
    wait(&wait_status);

    while (is_dynamic && WIFSTOPPED(wait_status)) {
        // Put breaking point at PLT instruction
        plt_address = ptrace(PTRACE_PEEKTEXT, pid, (void *) got_offset, NULL);
        plt_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) plt_address, NULL);
        plt_breakpoint = (plt_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, (void *) plt_address, (void *) plt_breakpoint);

        // Wait for arriving at PLT breakpoint
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);

        // On arriving to PLT instruction
        entry_counter++;
        // Fix PLT instruction
        ptrace(PTRACE_POKETEXT, pid, (void *) plt_address, (void *) plt_instruction);
        // Put breakpoint at rsp
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        orig_stack_ptr = regs.rsp;
        return_address = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, NULL);
        return_addr_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) return_address, NULL);
        return_break_point = (return_addr_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_break_point);
        // Set rip at PLT instruction again
        regs.rip--;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        while(!orig_reached){
            // Wait for arrival at return-address breakpoint
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&wait_status);
            // Fix return address instruction
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_addr_instruction);
            regs.rip--;
            value = (int) regs.rax; // function return value
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            if(regs.rsp >= orig_stack_ptr){
                orig_reached = true;
                print_run(entry_counter, value);
            } else {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_break_point);
            }
        }

        // GOT is now updated so can extract the function address
        func_address = ptrace(PTRACE_PEEKTEXT, pid, (void *) got_offset, NULL);
        is_dynamic = false;
    }

    func_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) func_address, NULL);
    func_break_point = (func_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, pid, (void *) func_address, (void *) func_break_point);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&wait_status);

    while (WIFSTOPPED(wait_status)) {
        orig_reached = false;
        entry_counter++;
        // Fix the instruction at function entrance
        ptrace(PTRACE_POKETEXT, pid, (void *) func_address, (void *) func_instruction);
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        orig_stack_ptr = regs.rsp;
        regs.rip--;
        // Put breakpoint at the return address
        return_address = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, NULL);
        return_addr_instruction = ptrace(PTRACE_PEEKTEXT, pid, (void *) return_address, NULL);
        return_break_point = (return_addr_instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_break_point);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        while(!orig_reached){
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&wait_status);
            // Arrival at return address
            // Fix return-address instruction
            ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_addr_instruction);
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            value = (int) regs.rax;
            regs.rip--;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            if(regs.rsp >= orig_reached){
                orig_reached = true;
                print_run(entry_counter, value);
            } else {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                ptrace(PTRACE_POKETEXT, pid, (void *) return_address, (void *) return_break_point);
            }
        }

        // Put another breakpoint at function address
        ptrace(PTRACE_POKETEXT, pid, (void *) func_address, (void *) func_break_point);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);
    }
}

bool isElf(char *file_path) {
    FILE *file = fopen(file_path, "r");
    char *initial_bytes = (char *) malloc(sizeof(char) * 5);

    int read_bytes = fread(initial_bytes, 1, 4, file);
    if (read_bytes < 4) {
        free(initial_bytes);
        fclose(file);
        return false;
    }
    initial_bytes[4] = '\0';

    bool is_elf = strcmp(initial_bytes + 1, "ELF") == 0;
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

bool getFunctionInfo(char *file_path, char *func_name, bool *isGlobal, bool *is_dynamic, unsigned long *func_address,
                     unsigned long *got_offset) {
    int fd;
    bool is_executable = false;
    unsigned long symbol_entries = 0, rellaoc_entries = 0;
    char *string_table, *str_tab, *dyn_str, *curr_name, *section_name;
    Elf64_Sym *dynamic_symbols, *rellaoc_table, *sym_tab;
    Elf64_Shdr *section_header_arr, string_section;
    Elf64_Ehdr *elf_header;
    void *elf;

    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        //TODO bad file
    }

    elf = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    elf_header = (Elf64_Ehdr *) elf;
    section_header_arr = (Elf64_Shdr *) ((char *) elf + elf_header->e_shoff); //getting section header
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

        if (section_header_arr[i].sh_type == 11 && strcmp(section_name, ".dynsym") == 0) {
            dynamic_symbols = (Elf64_Sym *) ((char *) elf + section_header_arr[i].sh_offset);
        }

        if (section_header_arr[i].sh_type == 4 && strcmp(section_name, ".rela.plt") == 0) {
            rellaoc_entries = section_header_arr[i].sh_size /
                              section_header_arr[i].sh_entsize; //size of section : size of each entry
            rellaoc_table = (Elf64_Sym *) ((char *) elf + section_header_arr[i].sh_offset);
        }

        if (section_header_arr[i].sh_type == 3 && strcmp(section_name, ".strtab") == 0) {
            if ((char *) elf + section_header_arr[i].sh_offset != string_table)
                str_tab = ((char *) elf +
                           section_header_arr[i].sh_offset); //getting the string table of the symbol table
        }

        if (section_header_arr[i].sh_type == 3 && strcmp(section_name, ".dynstr") == 0) {
            if ((char *) elf + section_header_arr[i].sh_offset != string_table)
                dyn_str = ((char *) elf +
                           section_header_arr[i].sh_offset); //getting the string table of the symbol table
        }
    }

    // Search for the function inside the symbol table
    for (int i = 0; i < symbol_entries; i++) {
        curr_name = str_tab + sym_tab[i].st_name; //the current symbol name in the string table of symbol table
        if (!strcmp(curr_name, func_name)) {
            if (ELF64_ST_BIND(sym_tab[i].st_info) == 1) {
                if (sym_tab[i].st_shndx == 0) { // st_shndx == 0 -> UND
                    *is_dynamic = true;
                }
                *func_address = sym_tab[i].st_value;
                *isGlobal = true;
            }
            is_executable = true;
        }
    }

    // Search for the GOT offset of the function if needed
    Elf64_Rela *currentPlt = (Elf64_Rela *) (rellaoc_table);
    if (is_dynamic) {
        for (int i = 0; i < rellaoc_entries; i++) {
            int entryIndex = ELF64_R_SYM(currentPlt->r_info);
            curr_name = dyn_str + dynamic_symbols[entryIndex].st_name;
            if (strcmp(curr_name, func_name) == 0) {
                *got_offset = currentPlt->r_offset; // Offset to GOT entry of func
                break;
            }
            currentPlt++;
        }
    }

    close(fd);
    return is_executable;
}
