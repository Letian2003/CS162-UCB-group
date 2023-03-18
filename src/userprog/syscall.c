#include "userprog/syscall.h"
#include "devices/shutdown.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "list.h"
#include "stddef.h"
#include "stdio.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "stdlib.h"
#include "threads/malloc.h"
#include "lib/float.h"


static void syscall_handler(struct intr_frame*);
static void check_vaddr(uint32_t* pd,void* p);
static void check_string(uint32_t* pd,char *s); 
static void check_pointer(uint32_t* pd,uint8_t* p);


void syscall_init(void) { 
    lock_init(&file_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

static void check_vaddr(uint32_t* pd,void* p){
    bool invalid = false;
    if(p==NULL || is_kernel_vaddr(p) || pagedir_get_page(pd,p) == NULL)
        invalid = true;
    if(invalid){
        // printf("invalid\n");
        sys_exit(-1);
    }
}

static void check_string(uint32_t* pd,char *s){
    for(int i=0;;i++){
        if(s[i]!='\0')
            check_vaddr(pd,s+i);
        else
            break;
    }
}

static void check_pointer(uint32_t* pd,uint8_t* p){
    check_vaddr(pd,p);
    check_vaddr(pd,p+3);
}


static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
    struct thread* cur_t = thread_current();
    struct process* pcb = cur_t->pcb;
    check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[0]);
    /*
    * The following print statement, if uncommented, will print out the syscall
    * number whenever a process enters a system call. You might find it useful
    * when debugging. It will cause tests to fail, however, so you should not
    * include it in your final submission.
    */

    // /* printf("System call number: %d\n", args[0]); */
    // if(args[0] >=4 && args[0]<=12 ){
    //     // printf("<sema down> pid = %d , args[0] = %d \n",get_pid(pcb),args[0]);
    //     lock_acquire(&file_lock);
    // }
    
    if (args[0] == SYS_PRACTICE) {
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        f->eax = args[1] + 1; 
    } 
    else if(args[0] == SYS_HALT){

        shutdown_power_off();
        //printf("NO HALT!!!\n");
    }
    else if (args[0] == SYS_EXIT) {
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        f->eax = args[1];
        sys_exit(args[1]);
    } 
    else if(args[0] == SYS_EXEC) {
        // printf("<exec> pid = %d\n",thread_current()->tid);
        check_string(cur_t->pcb->pagedir, (char*)args[1]);
        f->eax = sys_exec((const char*) args[1]);
    }
    else if(args[0] == SYS_WAIT){

        // printf("<wait>\n");
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        pid_t pid = args[1];
        // printf("pid=%d\n",pid);
        int status = process_wait(pid);
        // printf("status = %d\n",status);
        f->eax = status;
        // printf("</wait>\n");
    }

    else if(args[0] == SYS_CREATE){
        check_string(cur_t->pcb->pagedir, (char*)args[1]);
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[2]);

        char *file = (char*) args[1];
        unsigned initial_size = args[2];
        lock_acquire(&file_lock);
        f->eax = filesys_create(file,initial_size);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_REMOVE) {
        check_string(cur_t->pcb->pagedir, (char*)args[1]);
        char *file = (char*) args[1];
        lock_acquire(&file_lock);
        f->eax = filesys_remove(file);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_OPEN) {
        check_string(cur_t->pcb->pagedir, (char*)args[1]);
        lock_acquire(&file_lock);
        f->eax = sys_open((char*)args[1],pcb);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_FILESIZE){
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        
        lock_acquire(&file_lock);
        f->eax = sys_filesize(args[1],pcb);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_READ){
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[3]);
        check_string(cur_t->pcb->pagedir, (char*)args[2]);
        lock_acquire(&file_lock);
        f->eax = sys_read(args[1],(char*)args[2],args[3],pcb);
        lock_release(&file_lock);
        
    }
    
    else if (args[0] == SYS_WRITE) {
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[3]);
        check_string(cur_t->pcb->pagedir, (char*)args[2]);
        lock_acquire(&file_lock);
        f->eax = sys_write(args[1],(char*)args[2],args[3],pcb);
        lock_release(&file_lock);
        // printf("<pid = %d> write_size = %d\n",get_pid(pcb),f->eax);
    }

    else if(args[0] == SYS_SEEK){
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[2]);
        lock_acquire(&file_lock);
        sys_seek(args[1],args[2],pcb);
        lock_release(&file_lock);
    }

    else if(args[0] == SYS_TELL){
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        lock_acquire(&file_lock);
        f->eax = sys_tell(args[1], pcb);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_CLOSE){
        check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        lock_acquire(&file_lock);
        sys_close(args[1]);
        lock_release(&file_lock);
    }
    else if(args[0] == SYS_COMPUTE_E){
        // check_pointer(cur_t->pcb->pagedir, (uint8_t*)&args[1]);
        // int n = args[1];
        // f->eax = sys_sum_to_e(n);
    }

    // if(args[0] >=4 && args[0]<=12 ){
    //     // printf("<sema up> pid = %d , args[0] = %d \n",get_pid(pcb),args[0]);
    //     lock_release(&file_lock);
    // }
}

int sys_exec(const char* arg){
    // printf("<sys_exec>\n");
    pid_t pid = process_execute(arg);
    /**/
    if(pid == TID_ERROR){
        return -1;
    }
    // struct process_status* ps = get_ps(pid);
    // struct process *pcb = thread_current()->pcb;
    // struct children_process* cp = malloc(sizeof(struct children_process));
    // cp->ps = ps;
    // list_push_back(&pcb->children_processes , &cp->elem);
    // printf("</sys_exec>\n");
    return pid;
}

void sys_exit(int exit_status){
    struct process* pcb = thread_current()->pcb;
    pid_t pid = get_pid(pcb);
    struct process_status* ps = get_ps(pid);
    printf("%s: exit(%d)\n", pcb->process_name, exit_status,pid);
    /* ps */
    if(ps==NULL){
        printf("exitpid = %d , ps=NULL\n",pid);
    }
    if(ps!=NULL){
        ps->exit_status = exit_status;
        ps->is_exited = 1;
        // printf("<<<<");
        // prints_ps(ps);
    }
    /* debug 
    printf("<exit>\n");
    print_ps();
    printf("</exit>\n");
    printf("now : pid = %d\n",thread_current()->pcb->main_thread->tid);
    */

    process_exit();
}

void sys_close(int fd){
    struct file_status* fs = get_fs(fd); 
    struct process* pcb = thread_current()->pcb;
    if(fs == NULL ){
        return;
    }

    struct process_fd* pfd = NULL;
    for(struct list_elem* elem = list_begin(&pcb->fd_list); elem != list_end(&pcb->fd_list);
        elem = list_next(elem)){
            pfd = list_entry(elem,struct process_fd,elem);
            if(pfd==NULL || pfd->fs==NULL)
                continue;
            if(pfd -> fs -> fd == fd)
                break;
        }
    fs->is_closed = 1;
    // printf("<before close>\n");
    // print_fd();
    file_close(fs->fs_file);
    list_remove(&fs->elem);
    free(fs);
    

    if(pfd != NULL){
        list_remove(&pfd->elem);
        free(pfd);
    }
    // printf("<after  close>\n");
    // print_fd();
}

int sys_read(int fd,char* buffer,int size,struct process* pcb){
    if(fd == STDIN_FILENO){
        for(int i=0;i<size;i++){
            buffer[i] = input_getc();
        }
        return size;
    }
    else{
        struct file_status* fs = get_fs(fd);
        if(fs == NULL){
            return -1;
        }
        else{
            int read_size = file_read(fs->fs_file,buffer,size);
            return read_size;
        }
    }
}

int sys_write(int fd,char* buffer,int size,struct process* pcb){
    if (fd == STDOUT_FILENO) {
        putbuf(buffer,size);
        return size;
    }
    struct file_status* fs = get_fs(fd);
    if(fs == NULL ){
        // printf("NULL || vertify\n");
        return -1;
    }
    // if(fs->fs_file->deny_write){
    //     printf("deny_write\n");
    //     return -1;
    // }

    int write_size = file_write(fs->fs_file,buffer,size);
    return write_size;
}

int sys_filesize(int fd,struct process* pcb){
    // printf("<sys_filesize> fd = %d\n",fd);
    // print_fd();
    struct file_status* fs = get_fs(fd);
    if(fs == NULL){
        // printf("<file_size> NULL\n");
        return -1;
    }
    else{
        // printf("file_length = %d\n",file_length(fs->fs_file));
        return file_length(fs->fs_file);
    }
}

int sys_open(char* filename, struct process* pcb){
    struct file* File = filesys_open(filename);
    if(File==NULL){
        // printf("File is NULL\n");
        return -1;
    }
    else{
        // printf("pid = %d, filename is %s\n",get_pid(pcb),filename);
        struct file_status* fs = malloc(sizeof(struct file_status));
        if(fs == NULL){
            printf("malloc\n");
            process_exit();
        }
        fs->fd = pcb->fd_num;
        fs->fs_file = File;
        fs->is_closed = 0;
        pcb->fd_num++;
        list_push_back(&file_status_list, &fs->elem);
        struct process_fd* pf = malloc(sizeof(struct process_fd));
        if(pf == NULL){
            printf("malloc\n");
            process_exit();
        }
        pf->fs = fs;
        list_push_back(&pcb->fd_list, &pf->elem);
        // print_fd();
        return fs->fd;
    }
}

void sys_seek(int fd,int position,struct process* pcb){
    struct file_status* fs = get_fs(fd);
        if(fs == NULL){
            return;
        }
        fs->fs_file->pos = position;
}

int sys_tell(int fd,struct process* pcb){
    struct file_status* fs = get_fs(fd);
    if(fs == NULL){
        return -1;
    }
    return fs->fs_file->pos;
}