#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "list.h"
#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct lock file_lock;
struct process_status {
    pid_t pid;
    struct list_elem elem;
    int is_exited;
    int exit_status;
    int wait;
};
struct list process_all_status_list;
struct children_process{
    struct process_status* ps;
    struct list_elem elem;
};

struct file_status{
    struct list_elem elem;
    int fd;
    int is_closed;
    struct file* fs_file;
};
struct list file_status_list;
struct process_fd{
    struct file_status* fs;
    struct list_elem elem;
};

struct process {
  /* Owned by process.c. */
    uint32_t* pagedir;          /* Page directory. */
    char process_name[16];      /* Name of the main thread */
    struct thread* main_thread; /* Pointer to main thread */

    /* for syscall wait() */
    struct list children_processes;
    struct list fd_list;
    struct file* file;
    int fd_num;
};

void userprog_init(void);

pid_t process_execute(const char* task);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

struct process_status* get_ps(pid_t pid);

/* debug  */
void print_ps(void);
void prints_ps(struct process_status* ps);
void print_cp(struct list* children_processes);
void init_process_status(struct process_status* ps,int pid);
void destroy_children_processes(void);

struct file_status* get_fs(int fd);
bool vertify_pfd(struct process* pcb, int fd);
void destroy_fd_list(void);
void print_fd(void);

#endif /* userprog/process.h */
