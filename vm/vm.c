/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init(void) {
	vm_anon_init();
	
	vm_file_init();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
	page_get_type(struct page* page) {
	int ty = VM_TYPE(page->operations->type);
	switch (ty) {
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame* vm_get_victim(void);
static bool vm_do_claim_page(struct page* page);
static struct frame* vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer(enum vm_type type, void* upage, bool writable,
	vm_initializer* init, void* aux) {

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table* spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL) {
		
		//반환,  함수포인터,   함수의 인자
		bool (*initializer)(struct page *, enum vm_type, void *);
		
		switch (type)
		{
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:	
				goto err;
		}

		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. */
		struct page *create_page = (struct page*) malloc(sizeof(struct page));
		if (create_page == NULL){
			return false;
		}

		uninit_new (create_page, upage, init, type, aux, initializer );
		 /* TODO: You should modify the field after calling the uninit_new. */
		create_page->writable = writable;

		 /* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, create_page);
		
	}
err:
	return false;
}



/* Find VA from spt and return page. On error, return NULL. */
struct page*
	spt_find_page(struct supplemental_page_table* spt UNUSED, void* va UNUSED) {
	struct page* page = NULL;
	/* TODO: Fill this function. */
	/* project 3 virtual memory */
	/* TODO : 받아온 spt 사용처 */
	page = page_lookup(va); // va는 자체가 주소 &붙이면 안됨 
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page(struct supplemental_page_table* spt UNUSED, struct page* page UNUSED) {
	bool succ;
	/* struct page을 지정된 Supplemental Page Table에 삽입
	함수는 가상 주소가 지정된 SPT에 없는지 확인 */
	/* project 3 virtual memory */

	struct page* find_page = spt_find_page(spt, page->va);
	if (find_page == NULL)
	{
		succ = false;
	}
	else
	{
		succ = true;
		hash_insert(&spt->spt_hash, &page->hash_elem);
	}

	return succ;
}

void
spt_remove_page(struct supplemental_page_table* spt, struct page* page) {
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame*
vm_get_victim(void) {
	struct frame* victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame*
vm_evict_frame(void) {
	struct frame* victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame*
vm_get_frame(void) {
	struct frame* frame = NULL;
	/* project 3 virtual memory */
	/* TODO: Fill this function. */
	frame = (struct frame*)malloc(sizeof(frame));	
	ASSERT(frame != NULL);
	
	void *get_page = palloc_get_page(PAL_USER);

	if (get_page == NULL)
	{
		PANIC ("todo");
		frame->kva = NULL;
	}
	else
	{
		frame->kva = get_page;
	}	

	frame->page = NULL;
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void* addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page* page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault(struct intr_frame* f UNUSED, void* addr UNUSED,
	bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table* spt UNUSED = &thread_current()->spt;
	struct page* page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page(struct page* page) {
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page(void* va UNUSED) {
	struct page* page = NULL;
	/* TODO: Fill this function */
	
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
	{
		return false;
	}

	// 주어진 va,즉 페이지의 가상메모리 주소를 통해 페이지를 얻어옵니다.
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page* page) {
	struct frame* frame = vm_get_frame();
	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	// 실질적으로 Frame과 인자로 받은 Page를 연결해주는 역할을 수행합니다.
	/* Set links */
	frame->page = page;
	page->frame = frame;

	// 그러면 우선적으로 해당 페이지가 이미 어떠한 물리 주소(kva)와 미리 연결이 되어 있는지 확인해줘야합니다.
	if (pml4_get_page(thread_current()->pml4, page) != NULL)
	{
		return false;
	}
	// 이후 미리 연결된 kva가 없을 경우,해당 va를 kva에 set해줍니다.
	// 최종적으로 페이지와 프레임간의 연결이 완료되었을 경우,swap_in()을 통해 해당 페이지를 물리 메모리에 올려줍니다.	
	if (pml4_set_page(thread_current()->pml4, page->va, frame->kva, true))
	{
		return swap_in(page, frame->kva);
	}

	return false;

	
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init(struct supplemental_page_table* spt UNUSED) {
	/* project 3 virtual memory */
	/* TODO : 반환형을 보고 무언가를 해야하는가*/
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);

}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy(struct supplemental_page_table* dst UNUSED,
	struct supplemental_page_table* src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill(struct supplemental_page_table* spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}

/* project 3 virtual memory */
/* Returns the page containing the given virtual address, or a null pointer if no such page exists. */
struct page*
	page_lookup(const void* address) {
	struct page p;
	struct hash_elem* e;
	struct thread* curr = thread_current();

	p.va = address;

	e = hash_find(&(curr->spt.spt_hash), &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}