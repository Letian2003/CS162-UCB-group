#include "userprog/process.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


void syscall_init(void);
void sys_exit(int exit_status);
void sys_close(int fd);
int sys_open(char* filename, struct process* pcb);
int sys_filesize(int fd,struct process* pcb);
int sys_read(int fd,char* buffer,int size,struct process* pcb);
int sys_write(int fd,char* buffer,int size,struct process* pcb);
void sys_seek(int fd,int position,struct process* pcb);
int sys_tell(int fd,struct process* pcb);
int sys_exec(const char* arg);

#endif /* userprog/syscall.h */
