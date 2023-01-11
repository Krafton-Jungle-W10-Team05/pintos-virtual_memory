#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h" 	// filesys_* func
#include "filesys/file.h"		// file_* func
#include "threads/vaddr.h"		// is_user_vaddr
// #include "lib/user/syscall.h" 	// pid_t
#include "threads/palloc.h" 	// palloc_get_page
#include "lib/stdio.h" 			// predefined fd
#include "threads/synch.h" 		// lock

typedef int pid_t; // #include "lib/user/syscall.h" -> type conflict 발생으로 인한 재정의

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
/*------------------------- [P2] System Call --------------------------*/

void check_address(void *addr);
void get_argument(void *rsp, int argc, void *argv[]);
void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *file);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/*------------------------- [P2] System Call - fd function --------------------------*/
int fdt_add_fd(struct file *f); //
struct file *fdt_get_file(int fd); //
void fdt_remove_fd(int fd); //

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	/*------------------------- [P2] System Call --------------------------*/	
	lock_init(&filesys_lock);
}

/* The main system call interface */
/*------------------------- [P2] System Call --------------------------*/
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	struct thread *curr = thread_current();

	switch (f->R.rax) // 시스템 콜 번호에 따라 분기
	{
	case SYS_HALT:
		halt ();
		break;
	case SYS_EXIT:
		exit (f->R.rdi);
		break;
	case SYS_FORK:
		// memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame));
		f->R.rax = fork (f->R.rdi, f);
		break;
	case SYS_EXEC:
		if (exec (f->R.rdi) == -1)
			exit (-1);
		break;
	case SYS_WAIT:
		f->R.rax = wait (f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create (f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove (f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open (f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize (f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek (f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell (f->R.rdi);
		break;
	case SYS_CLOSE:
		close (f->R.rdi);
		break;
	default:
		exit (-1);
		break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

/*------------------------- [P2] System Call --------------------------*/
/**
 * @brief 주소 값이 유효한 주소 영역인지 확인
 * @details 사용자가 Null 포인터 @n 매핑되지 않은 가상 메모리에 대한 포인터 @n 커널 가상 주소 공간에 대한 포인터(KERN_BASE)
 * @param addr 
 */
void 
check_address(void *addr) {
 	struct thread *curr = thread_current();
	if (!is_user_vaddr(addr) || pml4_get_page(curr -> pml4, addr) == NULL || addr == NULL) // 유저 영역인지  NULL 포인터인지 확인
		exit(-1);
}

/**
 * @brief 핀토스 자체를 종료시키는 시스템 콜
 * 
 */
void 
halt(void) {
	power_off();
}

/**
 * @brief 현재 프로세스를 종료시키는 시스템 콜
 * @details 종료 시 출력 : "${프로세스 명}: exit(${프로세스 상태})\n" @n process_exit()에 존재
 * @param status 정상 종료 시, 0
 */
void 
exit(int status) {
	struct thread *curr = thread_current();
	curr->wait_status_p->exit_code = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t fork (const char *thread_name, struct intr_frame *f) {
	check_address(thread_name);
	return process_fork(thread_name, f);
}

int exec (const char *file){
	check_address(file);

	int size = strlen(file) + 1; // 파일 사이즈(NULL 포함하기 위해 +1)
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if (fn_copy == NULL)// 메모리 할당 불가 시
		exit(-1);
	strlcpy(fn_copy, file, size);

	if (process_exec(fn_copy) == -1) // [process_exec] 'load (file_name, &_if);' -> load 실패 시
		return -1;
	
	NOT_REACHED(); // ! 뭔지 더 알아보기

	return 0;
}

int wait (tid_t pid){
	process_wait(pid);
}

/**
 * @brief 파일을 생성하는 시스템 콜
 * @details filesys_create (const char *name, off_t initial_size)
 * @param file 생성할 파일의 이름 및 경로 정보
 * @param initial_size 생성할 파일의 크기
 * @return true 성공
 * @return false 실패
 */
bool 
create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

/**
 * @brief 파일을 샂게하는 시스템 콜
 * 
 * @param file 제거할 파일의 이름 및 경로 정보
 * @return true 성공
 * @return false 실패
 */
bool 
remove(const char *file){
	check_address(file);
	return filesys_remove(file);
}


/**
 * @brief 파일을 열 때 사용하는 시스템 콜
 * 
 * @param file 파일의 이름 및 경로 정보
 * @return int 성공 시 fd, 실패 시 -1
 */
int 
open (const char *file){
	check_address(file);
	lock_acquire(&filesys_lock);
	struct file *target_file = filesys_open(file);

	if (target_file == NULL) {
		return -1;
	}
	int fd = fdt_add_fd(target_file); // fdt : file data table

	// fd table이 가득 찼다면
	if (fd == -1) {
		file_close(target_file);
	}
	lock_release(&filesys_lock);
	return fd;
}

/**
 * @brief 파일의 크기를 알려주는 시스템 콜
 * 
 * @param fd  
 * @return int 성공 시 파일 크기, 실패 시 -1 
 */
int 
filesize (int fd){
	struct file *target_file = fdt_get_file(fd);
	if (target_file == NULL)
		return -1;
	return file_length(target_file);
}

/**
 * @brief 열린 파일의 데이터를 읽는 시스템 콜
 * 
 * @param fd 
 * @param buffer 읽은 데이터를 저장할 버퍼의 주소 값
 * @param length 읽을 데이터 크기
 * @return int 
 */
int 
read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	int read_bytes = -1;

	if(fd == STDIN_FILENO){ // fd 0 reads from the keyboard using input_getc()._gitbook
		int i;
		unsigned char *buf = buffer;
			
		for (i = 0; i < size; i++)
		{
			char c = input_getc();
			*buf++ = c;
			if (c == '\0')
				break;
		}
		return i;

	}
	else{
		struct file *file = fdt_get_file(fd);
		if (file != NULL && fd != STDOUT_FILENO){ // STDOUT_FILENO 
			lock_acquire(&filesys_lock); // 파일을 읽는 동안은 접근 못하게 락 걸어줌
			read_bytes = file_read(file, buffer, size);
			lock_release(&filesys_lock); // 락 해제
		}
	}
	return read_bytes;
}

/**
 * @brief 열린 파일에 데이터를 쓰는 시스템 콜
 * 
 * @param fd 
 * @param buffer 
 * @param size 
 * @return int 
 */
int
write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int write_bytes = -1;

	if (fd == STDOUT_FILENO){
		putbuf (buffer, size);
		return size;
	}
	else {
		struct file *file = fdt_get_file(fd);
		if (file != NULL && fd != STDIN_FILENO){ // STDIN_FILENO
			lock_acquire(&filesys_lock); // 파일을 쓰는 동안은 접근 못하게 락 걸어줌
			write_bytes = file_write(file, buffer, size);
			lock_release(&filesys_lock); // 락 해제
		}
	}
	return write_bytes;
}

/**
 * @brief 열린 파일의 위치를 이동하는 시스템 콜
 * 
 * @param fd 
 * @param position 현재 위치(offset)를 기준으로 이동할 거리
 */
void 
seek (int fd, unsigned position){
	struct file *target_file = fdt_get_file(fd);

	if (fd <= STDOUT_FILENO || target_file == NULL)
		return;
	
	file_seek(target_file, position);
}

/**
 * @brief 열린 파일의 위치를 알려주는 시스템 콜
 * 
 * @param fd 
 * @return unsigned 성공 시 파일의 위치(offset), 실패 시 -1
 */
unsigned 
tell (int fd){
	struct file *target_file = fdt_get_file(fd);

	if (fd <= STDOUT_FILENO || target_file == NULL)
		return;

	file_tell(target_file);
}

/**
 * @brief 열린 파일을 닫는 시스템 콜
 * @details 파일을 닫고 fd를 제거한다.
 * @param fd 
 */
void
close (int fd){
	struct file *target_file = fdt_get_file(fd);

	if (fd <= STDOUT_FILENO || target_file == NULL || target_file <= 2)
		return;
	
	fdt_remove_fd(fd); // fd table에서 해당 fd값을 제거한다.

	// file_close(target_file); // filesys에 구현된 file_close를 이용해, 해당 파일을 닫는다.
}


/*------------------------- [P2] System Call - fd function --------------------------*/

/**
 * @brief fd table에 해당 파일 저장, fd 생성
 * @details Hanyang Univ. process_add_file 각색
 * @param f 새로 fd를 생성하려는 파일 객체(*file)
 * @return int 성공 시 fd, 실패 시 -1(STDERR_FILENO)
 */
int 
fdt_add_fd(struct file *f) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;

	// fd가 제한 범위를 넘지 않고 fdt의 인덱스 위치와 일치 시
	while (curr->next_fd < FDCOUNT_LIMIT && fdt[curr->next_fd]) {
		curr->next_fd++;
	}

	// fdt가 가득 찼을 때 return -1
	if (curr->next_fd >= FDCOUNT_LIMIT)
		return -1;

	fdt[curr->next_fd] = f; // fdt에 해당 fd 새로 넣어줌
	return curr->next_fd;
}

/**
 * @brief fd table에서 param fd 검색 
 * @details Hanyang Univ. process_get_file 각색
 * @param fd 
 * @return struct file* 성공 시 찾은 fd에 대한 파일 객체, 실패 시 NULL
 */
struct file *
fdt_get_file(int fd) {
	struct thread *curr = thread_current();
	if (fd < STDIN_FILENO || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	return curr->fdt[fd];
}


/**
 * @brief fd table에서 param fd 제거
 * @details Hanyang Univ. process_close_file 각색
 * @param fd 
 */
void 
fdt_remove_fd(int fd) {
	struct thread *curr = thread_current();

	if (fd < STDIN_FILENO || fd >= FDCOUNT_LIMIT)
		return;
	
	curr->fdt[fd] = NULL;
}
