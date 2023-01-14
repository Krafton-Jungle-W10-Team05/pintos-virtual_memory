#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#define VM
#ifdef VM
#include "vm/vm.h"
#endif

#include "lib/user/syscall.h" // need to Calling syscall_close.

static void process_cleanup(void);
static bool load(const char* file_name, struct intr_frame* if_);
static void initd(void* f_name);
static void __do_fork(void*);

/*------------------------- [P2] Argument Passing --------------------------*/
static void argument_parse(char* file_name, int* argc_ptr, char* argv[]);
static void argument_stack(int argc, char** argv, struct intr_frame* if_);

/*------------------------- [P2] System Call - Thread --------------------------*/
struct wait_status* get_child_wait_satus(int pid);

struct file_infomation {
    off_t offset;
    size_t page_read_byte;
    struct file *file;
};


/* General process initializer for initd and other process. */
static void
process_init(void) {
	struct thread* current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
 /*------------------------- [P2] Argument Passing --------------------------*/
tid_t
process_create_initd(const char* file_name) {
	char* fn_copy, * save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);
	/* Create a new thread to execute FILE_NAME. */
	strtok_r(file_name, " ", &save_ptr); // 실행 파일 이름 파싱
	// ↳해당 라인을 추가하지 않으면 커맨드 라인 전체가 스레드 이름으로 지정된다.
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void* f_name) {
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif
	process_init();
	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork(const char* name, struct intr_frame* if_ UNUSED) {
	/* Clone current thread to new thread.*/

	struct thread* curr = thread_current();

	memcpy(&curr->parent_if, if_, sizeof(struct intr_frame)); // 전달받은 intr_frame을 현재 parent_if에 복사한다.

	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr); // __do_fork를 실행하는 스레드 생성, 현재 스레드를 인자로 넘겨준다.
	if (tid == TID_ERROR)
		return TID_ERROR;

	struct wait_status* child_status = get_child_wait_satus(tid);
	sema_down(&child_status->fork); // wait until child loads
	if (child_status->exit_code == -1)
		return TID_ERROR;

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t* pte, void* va, void* aux) {
	struct thread* current = thread_current();
	struct thread* parent = (struct thread*) aux;
	void* parent_page;
	void* newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
	{
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page(parent->pml4, va);

	if (parent_page == NULL)
	{
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
	{
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page(current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void* aux) {
	struct intr_frame if_;
	struct thread* parent = (struct thread*) aux;
	struct thread* current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame* parent_if;
	bool succ = true;

	parent_if = &parent->parent_if; // process_fork에서 복사 해두었던 intr_frame
	/* 1. Read the cpu context to local stack. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));

	if_.R.rax = 0; // ! if_의 리턴값을 0으로 설정?

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (parent->next_fd == FDCOUNT_LIMIT)
		goto error;

	for (int i = 0; i < FDCOUNT_LIMIT; i++) {
		struct file* file = parent->fdt[i];
		if (file == NULL)
			continue;

		// If 'file' is already duplicated in child, don't duplicate again but share it
		bool found = false;
		if (!found) {
			struct file* new_file;
			if (file > 2)
				new_file = file_duplicate(file);
			else
				new_file = file;

			current->fdt[i] = new_file;
			// for문부터 여기까지 코드가 file descriptor 내용을 복사한다 
		}
	}

	current->next_fd = parent->next_fd;
	sema_up(&current->wait_status_p->fork);
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret(&if_);
error:
	current->wait_status_p->exit_code = TID_ERROR;
	sema_up(&current->wait_status_p->fork);
	exit(TID_ERROR);
	// thread_exit ();
}

/*------------------------- [P2] Argument Passing --------------------------*/
/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec(void* f_name) {
	char* file_name = f_name; // 실행할 파일 이름(argv[0])
	// char *file_name_copy[48];
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	int argc = 0;
	char* argv[128]; // 64bit computer(uint64_t : 8byte)

	/* We first kill the current context */
	process_cleanup();

	/* 커맨드 라인을 파싱한다. */
	argument_parse(file_name, &argc, argv);

	/* And then load the binary */
	success = load(file_name, &_if);


	/* If load failed, quit. */
	if (!success) {
		palloc_free_page(file_name);
		return -1;
	}

	/* Initialize interrupt frame and load executable. */
	// argument_stack(argv, argc, &_if.rsp);
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);

	argument_stack(argc, argv, &_if); // argc, argv로 커맨드 라인 파싱
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true); // 메모리에 적재된 상태 출력

	/* Start switched process. */
	do_iret(&_if);
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait(tid_t child_tid UNUSED) {
	int exit_status;
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	* XXX:       to add infinite loop here before
	* XXX:       implementing the process_wait. */

	/* project2 bug fix */
	struct thread* curr = thread_current();
	struct list_elem* e;
	int find_waited_thread = 0;
	struct wait_status* ws;
	for (e = list_begin(&curr->child_wait_list); e != list_end(&curr->child_wait_list); e = list_next(e))
	{
		ws = list_entry(e, struct wait_status, wait_elem);
		if (ws->tid == child_tid)
		{
			find_waited_thread = 1;
			break;
		}
	}
	if (find_waited_thread == 0)
	{
		return -1;
	}


	sema_down(&ws->dead);

	exit_status = ws->exit_code;

	list_remove(&ws->wait_elem);
	free(ws);

	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit(void) {
	struct thread* curr = thread_current();
	int ref_cnt1;
	int ref_cnt2;
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	 // printf("in exit current tid %d\n", curr->tid);
	 /* project 2 bug fix*/

	for (int i = 2; i < FDCOUNT_LIMIT; i++) { // 프로세스 종료 시, 메모리 누수 방지를 위해 프로세스에 열린 모든 파일 닫음
		close(i);
	}

	palloc_free_multiple(curr->fdt, FDT_PAGES); // fd table 메모리 해제
	file_close(curr->running); // 현재 프로세스가 실행중인 파일을 종료한다.	
	process_cleanup();

	/* project 2 bug fix*/
	struct list_elem* e;
	e = list_begin(&curr->child_wait_list);
	while (e != list_end(&curr->child_wait_list)) {
		struct wait_status* ws = list_entry(e, struct wait_status, wait_elem);
		// printf("child tid %d\n", ws->tid);
		lock_acquire(&ws->lock);
		ref_cnt1 = --ws->ref_cnt;
		lock_release(&ws->lock);
		if (ref_cnt1 <= 0)
		{
			e = list_remove(&ws->wait_elem);
			free(ws);
		}
		else
		{
			e = list_next(e);
		}
	}

	lock_acquire(&curr->wait_status_p->lock);
	ref_cnt2 = --curr->wait_status_p->ref_cnt;
	lock_release(&(curr->wait_status_p)->lock);

	if (ref_cnt2 <= 0)
	{
		free(curr->wait_status_p);
	}
	else
	{
		sema_up(&curr->wait_status_p->dead);
	}



}


/* Free the current process's resources. */
static void
process_cleanup(void) {
	struct thread* curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t* pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate(struct thread* next) {
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

 /* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame* if_);
static bool validate_segment(const struct Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage,
	uint32_t read_bytes, uint32_t zero_bytes,
	bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char* file_name, struct intr_frame* if_) {
	struct thread* t = thread_current();
	struct ELF ehdr;
	struct file* file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* Open executable file. */
	file = filesys_open(file_name);
	if (file == NULL) {
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	t->running = file;

	file_deny_write(file); // 현재 오픈한 파일에 접근 못하게 함

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
		|| memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7)
		|| ehdr.e_type != 2
		|| ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1
		|| ehdr.e_phentsize != sizeof(struct Phdr)
		|| ehdr.e_phnum > 1024) {
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file)) {
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0) {
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
						- read_bytes);
				}
				else {
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void*) mem_page,
					read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	 /* 커맨드 라인을 파싱한다. */
	 // argument_stack(argc, argv, if_->rsp, &if_);
	 // argument_stack(arg_list, token_count, &if_);

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr* phdr, struct file* file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void*) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void*) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

 /* load() helpers. */
static bool install_page(void* upage, void* kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file* file, off_t ofs, uint8_t* upage,
	uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t* kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page(kpage);
			return false;
		}
		
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame* if_) {
	uint8_t* kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page(((uint8_t*) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void* upage, void* kpage, bool writable) {
	struct thread* t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL
		&& pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page* page, void* aux) {
	/* TODO: Load the segment from the file */
	// 프로세스가 uninit_page로 처음 접근하여 page_fault가 발생하면 해당 함수가 호출된다.
	// 호출된 page를 frame과 맵핑(do calm 쪽에서 미리해줌)하고 해당 page에 연결된 물리 메모리에 file 정보를 load 해준다.
	struct frame *load_frame = page->frame;
	struct file_information *file_info =  (struct file_information *)aux;
	
	// struct file* file = file_info->file;
	// off_t offset = file_info->offset;
	// size_t read_bytes = file_info->page_read_byte;
	// size_t zero_bytes = PGSIZE - read_bytes;

	struct file *file = ((struct file_information *)aux)->file;
	off_t offset = ((struct file_information *)aux)->offset;
	size_t page_read_bytes = ((struct file_information *)aux)->page_read_byte;
	size_t page_zero_bytes = PGSIZE - page_read_bytes;

	file_seek (file, offset);
	/* 페이지에 매핑된 물리 메모리(frame, 커널 가상 주소)에 파일의 데이터를 읽어온다. */
	/* 제대로 못 읽어오면 페이지를 FREE시키고 FALSE 리턴 */
	if (file_read(file, load_frame->kva, page_read_bytes) != (int)page_read_bytes)
	{
		palloc_free_page(load_frame->kva);
		// free(aux);
		return false;
	}
	
	memset(load_frame->kva + page_read_bytes, 0, page_zero_bytes);
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	return true;
	/* test*/
	//   bool success = true;
    // struct file_information *info = (struct file_information *)aux;
    // if (file_read_at(info->file, page->va, info->page_read_byte, info->offset) != (off_t)info->page_read_byte)
    // {
    //     vm_dealloc_page(page);
    //     success = false;
    // }
    // else
    // {
    //     memset((page->va) + info->page_read_byte, 0, PGSIZE - info->page_read_byte);
    // }

    // file_close(info->file);
    // free(aux);
    // return success;
	
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file* file, off_t ofs, uint8_t* upage,
	uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	// file_information 구조체를 추가하여 file을 load 할 때 필요한 file,
	// offset, read_bytes를 저장하고 initializer를 호출하고 aux 인자로 넘겨준다.
	// 파일을 page 단위로 끊어서 uninit 페이지로 만들고 file 정보를 page에 저장하고 SPT에 추가한다.

	/* upage 주소부터 1페이지 단위씩 UNINIT 페이지를 만들어 프로세스의 spt에 넣는다(vm_alloc_page_with_initializer).
		이 때 각 페이지의 타입에 맞게 initializer도 맞춰준다. */

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// load_segment에서 일단 vm_alloc_page_with_initializer 통해 VM_UNINIT 타입의 페이지를 생성해 놓은 뒤
		// 후에 page_fault로 initialize가 될 때 lazy_load_segment로 initialize를 하는 방식이다. 
		//argument passing이 이루어지는 첫 번째 stack page는 eager loading을 허용한다고 매뉴얼에 나오니 참고
		struct file_information *file_info = (struct file_information*)malloc(sizeof(struct file_information));
		file_info->file = file;
		file_info->offset = ofs;
		file_info->page_read_byte = read_bytes;
		
		
		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void* aux = file_info;
		
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
			writable, lazy_load_segment, (void *)aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame* if_) {
	 bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */
    // success = vm_alloc_page(VM_ANON, stack_bottom, true);
    // if (success)
    // {
    //     struct page *pg = spt_find_page(&thread_current()->spt, stack_bottom);

    //     if (vm_claim_page(stack_bottom))
    //         if_->rsp = (uintptr_t)USER_STACK;
    // }

    // return success;

}
#endif /* VM */

/*------------------------- [P2] Argument Passing --------------------------*/
static void argument_parse(char* file_name, int* argc_ptr, char* argv[]) {
	char* token, * save_ptr;

	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
		argv[(*argc_ptr)++] = token;

	argv[*argc_ptr] = token;
}

static void argument_stack(int argc, char** argv, struct intr_frame* if_) {
	char* argv_addr[128];
	for (int i = argc - 1; i >= 0; i--) { // argument
		if_->rsp -= strlen(argv[i]) + 1;
		// if_->rsp = argv[i];
		memcpy(if_->rsp, argv[i], strlen(argv[i]) + 1); // *(if_->rsp) = *argv[1]; 'if_->rsp'의 크기를 몰라서 이렇게 하면 안됨
		argv_addr[i] = if_->rsp;
	}

	while (if_->rsp % 8 > 0) { // word-aline padding
		if_->rsp -= 1;
		memset(if_->rsp, 0, 1);
	}

	if_->rsp -= sizeof(char*);
	memset(if_->rsp, 0, sizeof(char*));

	for (int i = argc - 1; i >= 0; i--) {
		if_->rsp -= sizeof(char*);
		// if_->rsp = argv_addr[i];
		memcpy(if_->rsp, &argv_addr[i], sizeof(char*));
	}

	if_->rsp -= sizeof(char*);
	memset(if_->rsp, 0, sizeof(char*));

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp + 8;
}


/*------------------------- [P2] System Call - Thread --------------------------*/
struct wait_status* get_child_wait_satus(int pid) {
	struct thread* curr = thread_current();
	struct list* child_list = &curr->child_wait_list;

	// 자식 리스트를 순회하면서 프로세스 디스크립터 검색
	for (struct list_elem* e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct wait_status* ws = list_entry(e, struct wait_status, wait_elem);
		if (ws->tid == pid) // 해당 pid가 존재하면 프로세스 디스크립터 리턴
			return ws;
	}
	return NULL; // 리스트에 존재하지 않으면 NULL
}