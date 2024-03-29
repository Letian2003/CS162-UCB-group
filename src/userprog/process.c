#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "stddef.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);


/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
    struct thread* t = thread_current();
    bool success;

    /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
    t->pcb = calloc(sizeof(struct process), 1);
    success = t->pcb != NULL;
    t->pcb->main_thread = t;
    t->pcb->fd_num = 2;

    list_init(&t->pcb->children_processes);
    list_init(&t->pcb->fd_list);
    /* process_status */
    list_init(&process_all_status_list);
    list_init(&file_status_list);
    
    struct process_status* ps = malloc(sizeof(struct process_status)); 
    if(ps == NULL){
        printf("malloc\n");
        process_exit();
    }
    init_process_status(ps, t->tid);

    /* Kill the kernel if we did not succeed */
    ASSERT(success);
}

struct arguments {
    char* fn_copy;
    char** argv;
    int argc;
    struct file* File;
    struct semaphore sema;
    int status;
};

static void free_args(struct arguments* args) {
    for (int i = 0; i < args->argc; i++) {
        free(args->argv[i]);
    }
    free(args->argv);
}

static void push_arg(struct arguments* args, char* arg) {
    args->argv = (char**)realloc(args->argv, sizeof(char*) * (args->argc + 1));
    if (args->argv == NULL) {
        printf("Realloc failed.");
        process_exit();
    }
    args->argv[args->argc] = arg;
    args->argc++;
}

static void parse_to(struct arguments* args, const char* task) {
    args->argv = NULL;
    args->argc = 0;
    

    char *token = NULL, *psave = NULL;
    int len = strlen(task);
    char* str = malloc(len + 1);
    if (str == NULL) {
        printf("Malloc failed.");
        process_exit();
    }
    strlcpy(str, task, len + 1);

    token = strtok_r(str, " ", &psave);
    while (token != NULL) {
        len = strlen(token);
        char* arg = malloc(len + 1);
        if (arg == NULL) {
            printf("Malloc failed.");
            process_exit();
        }
        strlcpy(arg, token, len + 1);
        push_arg(args, arg);
        token = strtok_r(NULL, " ", &psave);
    }
    free(str);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* task ) {
    struct arguments* args = malloc(sizeof(struct arguments));
    if (args == NULL) {
        printf("Malloc failed.");
        process_exit();
    }
    parse_to(args, task);

    const char* file_name = args->argv[0];
    tid_t tid;

    sema_init(&temporary, 0);
    /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
    args->fn_copy = palloc_get_page(0);
    if (args->fn_copy == NULL)
        return TID_ERROR;
    strlcpy(args->fn_copy, file_name, PGSIZE);

    /* exec-missing */
    /* if file_name doesn't exist , return -1 */

    // printf("<process_execute 1>\n");
    lock_acquire(&file_lock);
    struct file* file = filesys_open(file_name);
    lock_release(&file_lock);
    if (file == NULL){
        tid = TID_ERROR;
    }
    else{
        args->File = file;
        args->status = 1;
        sema_init(&args->sema,0);
        /* Create a new thread to execute FILE_NAME. */
        tid = thread_create(file_name, PRI_DEFAULT, start_process, args);
        while(!sema_try_down(&args->sema)){
            thread_yield();
        }

        if(args->status == 0){
            tid = TID_ERROR;
        }
        /* process_status */
    }
    
    // printf("<process_execute 2>\n");
    // if (tid == TID_ERROR)
    //     palloc_free_page(args->fn_copy);
    
    // if (tid != TID_ERROR){
    //     struct process_status* new_ps = malloc(sizeof(struct process_status)); 
    //     init_process_status(new_ps , tid);
    // }

    // printf("<process_execute>\n");
    // print_ps();

    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* aux) {
    struct arguments* args = (struct arguments*)aux;
    char* file_name = (char*)args->fn_copy;
    struct file* file = args->File;
    struct thread* t = thread_current();
    struct intr_frame if_;
    bool success, pcb_success;

    /* Allocate process control block */
    struct process* new_pcb = malloc(sizeof(struct process));
    success = pcb_success = new_pcb != NULL;
    /* Allocate process_status */

    
    /* Initialize process control block */
    if (success) {
        // Ensure that timer_interrupt() -> schedule() -> process_activate()
        // does not try to activate our uninitialized pagedir
        new_pcb->pagedir = NULL;
        list_init(&new_pcb->children_processes);
        list_init(&new_pcb->fd_list);

        t->pcb = new_pcb;
        t->pcb->main_thread = t;
        t->pcb->fd_num = 2;

        /* debug 
        print_ps();
        */
        t->pcb->file = file;
        file_deny_write(file);

        /* malloc ps */
        struct process_status* new_ps = malloc(sizeof(struct process_status)); 
        if(new_ps == NULL){
            printf("malloc\n");
            process_exit();
        }
        int pid = thread_current()->tid;
        init_process_status(new_ps , pid);
        
        struct children_process* cp = malloc(sizeof(struct children_process));
        if(cp == NULL){
            printf("malloc\n");
            process_exit();
        }
        cp->ps = new_ps;
        list_push_back(&new_pcb->children_processes , &cp->elem);

        // Continue initializing the PCB as normal
        
        strlcpy(t->pcb->process_name, t->name, sizeof t->name);
        // print_ps();
    }

    
    // file_allow_write(file);

    /* Initialize interrupt frame and load executable. */
    if (success) {
        memset(&if_, 0, sizeof if_);
        if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
        if_.cs = SEL_UCSEG;
        if_.eflags = FLAG_IF | FLAG_MBS;
        lock_acquire(&file_lock);
        // printf("<load 1>\n");
        success = load(file_name, &if_.eip, &if_.esp);
        // printf("<load 2>\n");
        lock_release(&file_lock);
    }
    
    /* Handle failure with succesful PCB malloc. Must free the PCB */
    if (!success && pcb_success) {
        // Avoid race where PCB is freed before t->pcb is set to NULL
        // If this happens, then an unfortuantely timed timer interrupt
        // can try to activate the pagedir, but it is now freed memory
        struct process* pcb_to_free = t->pcb;
        t->pcb = NULL;
        free(pcb_to_free);
    }
    
    args->status = (int) success; 
    sema_up(&args->sema);
    /* Clean up. Exit on failure or jump to userspace */
    palloc_free_page(file_name);
    if (!success) {
        sema_up(&temporary);
        thread_exit();
    }
    
    /* Simulate the Program Startup. */
    char** argv = malloc(sizeof(char*) * args->argc);
    if (argv == NULL) {
        printf("Malloc failed.");
        thread_exit();
    }

    int total_len = 0;
    for (int i = args->argc - 1; i >= 0; --i) {
        int len = strlen(args->argv[i]);
        if_.esp -= len + 1;
        total_len += len + 1;
        memcpy(if_.esp, args->argv[i], len + 1);
        argv[i] = if_.esp;
    }
    argv[args->argc] = 0;

    total_len += (args->argc + 3) * 4;
    if (total_len % 16 != 0) {
        total_len = 16 - (total_len % 16);
    } else {
        total_len = 0;
    }
    if_.esp -= total_len;
    memset(if_.esp, 0, total_len);

    for (int i = args->argc; i >= 0; --i) {
        if_.esp -= 4;
        memcpy(if_.esp, &argv[i], 4);
    }
    free(argv);

    char* addr = if_.esp;
    if_.esp -= 4;
    memcpy(if_.esp, &addr, 4);
    if_.esp -= 4;
    memcpy(if_.esp, &args->argc, 4);
    free_args(args);

    /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
    if_.esp -= 4;

    
    // char buf[100];
    // hex_dump((unsigned int)if_.esp, buf, 100, true);
    // printf("%s", buf);
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
static bool vertify_child(struct process* pcb,pid_t child_pid){
    if(get_pid(pcb)<=1){
        return true;
    }
    
    struct list* children = &pcb->children_processes;
    for(struct list_elem* elem = list_begin(children); elem != list_end(children);elem = list_next(elem)){
        struct children_process* cp = list_entry(elem,struct children_process,elem);
        if(cp==NULL){
            continue;
        }
        struct process_status* ps = cp->ps;
        if(ps==NULL){
            continue;
        }
        // printf("<vertify_child>\n");
        // prints_ps(ps);
        if(ps->pid == child_pid){
            return true;
        }
    }
    return false;
}

int process_wait(pid_t child_pid) {
    // printf("<process_wait>\n");
    // printf("pid = %d\n",child_pid);


    struct process_status* ps = NULL;
    ps = get_ps(child_pid);
    for (struct list_elem* elem = list_begin(&thread_current()->pcb->children_processes); elem != list_end(&thread_current()->pcb->children_processes); elem = list_next(elem)){
        struct children_process* cp = list_entry(elem,struct children_process,elem);
        if(cp==NULL)
            continue;
        if(cp->ps->pid==child_pid){
            list_remove(elem);
            free(cp);
            break;
        }
    }

    if(ps==NULL){
        // printf("psNULL\n");
        // sema_up(&temporary);
        return -1;
    }
    while(!sema_try_down(&temporary)){
        thread_yield();
    }
    // printf("<wait 1 %d>\n",child_pid);
    struct process* pcb = thread_current()->pcb;
    
    if(ps->wait){
        
        printf("invalid child_pid\n");
        // printf("<ps->wait> = %d\n",ps->wait);
        sema_up(&temporary);
        return -1;
    }
    
    ps->wait=1;
    
    // printf("<wait 2 %d>\n",child_pid);
    while(ps!=NULL && !ps->is_exited){
        // printf("current : %d , child : %d , child->is_exited = %d\n",get_pid(pcb),child_pid,ps->is_exited);
        sema_up(&temporary);
        thread_yield();
        while(!sema_try_down(&temporary)){
            thread_yield();
        }
        
    }
    // printf("<wait 3 %d>\n",child_pid);
    int ret = ps->exit_status;

    list_remove(&ps->elem);
    free(ps);
    
    sema_up(&temporary);
    return ret;
}

/* Free the current process's resources. */
void process_exit(void) {
    struct thread* cur = thread_current();
    uint32_t* pd;

    /* If this thread does not have a PCB, don't worry */
    if (cur->pcb == NULL) {
        thread_exit();
        NOT_REACHED();
    }


    file_close(cur->pcb->file);
    destroy_fd_list();
    // destroy_children_processes();
    
    /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
    pd = cur->pcb->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
        cur->pcb->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }

    /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
    struct process* pcb_to_free = cur->pcb;
    
    cur->pcb = NULL ;
    // printf("<pexit pid> %d\n",pcb_to_free->main_thread->tid);
    free(pcb_to_free);

    sema_up(&temporary);
    thread_exit();
    
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
    struct thread* t = thread_current();

    /* Activate thread's page tables. */
    if (t->pcb != NULL && t->pcb->pagedir != NULL)
        pagedir_activate(t->pcb->pagedir);
    else
        pagedir_activate(NULL);

    /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
    struct thread* t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file* file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;
    

    /* Allocate and activate page directory. */
    t->pcb->pagedir = pagedir_create();
    if (t->pcb->pagedir == NULL)
        goto done;
    process_activate();
    

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }


    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
        ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) ||
        ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

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
                    uint32_t file_page = phdr.p_offset & ~PGMASK;
                    uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint32_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                     Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    } else {
                        /* Entirely zero.
                     Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes,
                                      writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp))
        goto done;

    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    file_close(file);

    return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
     user address space range. */
    if (!is_user_vaddr((void*)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t* kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
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

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
    uint8_t* kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
    struct thread* t = thread_current();

    /* Verify that there's not already a page at that virtual
     address, then map our page there. */
    return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
            pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
UNUSED static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}

struct process_status* get_ps(pid_t pid){
    struct process_status* ps = NULL;
    for(struct list_elem* e = list_begin(&process_all_status_list); e != list_end(&process_all_status_list) ;
        e = list_next(e)){
            ps = list_entry(e,struct process_status, elem);
            if(ps==NULL)
                continue;
            if(ps->pid == pid)
                break;
        }
    if(ps == NULL || ps->pid!=pid)
        return NULL;
    return ps;
}

void print_ps(void){
    struct process* pcb = thread_current()->pcb;
    // printf("<print_ps>\n");
    printf("<< process now : pid = %d , name = %s >>\n",get_pid(pcb),pcb->process_name);
    struct process_status* ps = NULL;
    for(struct list_elem* e = list_begin(&process_all_status_list); e != list_end(&process_all_status_list) ;
        e = list_next(e)){
            ps = list_entry(e,struct process_status, elem);
            if(ps==NULL)
                continue;
            printf("{ pid = %4d , is_exited = %1d ,exit_status = %1d }\n",ps->pid,ps->is_exited,ps->exit_status);
        }
    // printf("</print_ps>\n");
}

void prints_ps(struct process_status* ps){   
     printf("{ pid = %4d , is_exited = %1d ,exit_status = %1d }\n",ps->pid,ps->is_exited,ps->exit_status);;
}

void print_cp(struct list* children_processes){
    printf("<print_cp>\n");
    for(struct list_elem* elem = list_begin(children_processes);elem!=list_end(children_processes);
        elem = list_next(elem)){
            struct children_process* cp = list_entry(elem,struct children_process,elem);
            if(cp==NULL)
                continue;
            struct process_status* ps = cp->ps;
            if(ps==NULL)
                continue;
            prints_ps(ps); 
        }

    printf("</print_cp>\n");
}

void init_process_status(struct process_status* ps,pid_t pid){
    if(ps==NULL)
        return;
    ps->pid = pid;
    ps->is_exited = 0;
    ps->wait=0;
    ps->exit_status = 0;
    list_push_back(&process_all_status_list, &ps->elem);
}   

struct file_status* get_fs(int fd){
    struct process* pcb = thread_current() -> pcb;
    struct process_fd* pfd = NULL;
    for(struct list_elem* elem = list_begin(&pcb->fd_list); elem != list_end(&pcb->fd_list);
        elem = list_next(elem)){
            pfd = list_entry(elem,struct process_fd,elem);
            if(pfd==NULL || pfd->fs==NULL)
                continue;
            if(pfd->fs->fd == fd)
                break;
        }
    if(pfd==NULL || pfd->fs==NULL || pfd->fs->fd != fd)
        return NULL;
    return pfd->fs;
}

bool vertify_pfd(struct process* pcb, int fd){
    if(fd<2)
        return false;
    struct process_fd* pfd = NULL;
    for(struct list_elem* elem = list_begin(&pcb->fd_list); elem != list_end(&pcb->fd_list);
        elem = list_next(elem)){
            pfd = list_entry(elem,struct process_fd,elem);
            if(pfd==NULL)
                continue;
            if(pfd->fs->fd == fd)
                return true;
        }
    return false;
}

void destroy_fd_list(void){
    // printf("<destroy_fd_list>\n");
    // print_fd();
    struct process* pcb = thread_current() -> pcb;
    struct process_fd* pfd = NULL;
    struct list_elem* next = NULL;
    for(struct list_elem* elem = list_begin(&pcb->fd_list); elem != list_end(&pcb->fd_list);
        elem = next){
            next = list_next(elem);
            pfd = list_entry(elem,struct process_fd,elem);
            if(pfd==NULL || pfd->fs==NULL)
                continue;
            // printf("close %d\n",pfd->fs->fd);
            sys_close(pfd->fs->fd);
            
        }
    // printf("</destroy_fd_list>\n");
    // print_fd();
}

void print_fd(void){
    // printf("<print_fd>\n");
    struct process* pcb = thread_current() -> pcb;
    struct process_fd* pfd = NULL;
    // printf("<<pid = %d>>\n",get_pid(pcb));
    for(struct list_elem* elem = list_begin(&pcb->fd_list); elem != list_end(&pcb->fd_list);
        elem = list_next(elem)){
            pfd = list_entry(elem,struct process_fd,elem);
            if(pfd==NULL || pfd->fs==NULL)
                continue;
            printf("{ fd = %2d , is_closed = %d }\n",pfd->fs->fd,pfd->fs->is_closed);
        }
    // printf("</print_fd>\n");
}

void destroy_children_processes(void){
    
    struct process* pcb = thread_current() -> pcb;
    // printf("<destroy_children_processes>\n");
    // print_cp(&pcb->children_processes);
    struct list* children_processes = &pcb->children_processes;
    struct list_elem* nxt;
    for(struct list_elem* elem = list_begin(children_processes);elem!=list_end(children_processes);
        elem = nxt){
            nxt = list_next(elem);
            struct children_process* cp = list_entry(elem,struct children_process,elem);
            if(cp==NULL)
                continue;
            struct process_status* ps = cp->ps;
            if(ps==NULL)
                continue;
            list_remove(&ps->elem);
            free(ps);
            list_remove(elem);
            free(cp);
    }
    // printf("</destroy_children_processes>\n");
    // print_cp(&pcb->children_processes);
}