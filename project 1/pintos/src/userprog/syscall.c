#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/exception.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *syscall_number = f->esp;
  memory_protection (syscall_number);

  switch (*syscall_number) {
    case SYS_HALT:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
    case SYS_EXIT:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      f->eax = exec((const char *)*(uint32_t *)(syscall_number[1]));
      break;
    case SYS_WAIT:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      f->eax = wait((pid_t)*(uint32_t *)(syscall_number[1]));
      break;
    case SYS_CREATE:
      if (!is_user_vaddr(&syscall_number[1]) || !is_user_vaddr(&syscall_number[2]))
        exit (-1);
      break;
    case SYS_REMOVE:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
    case SYS_OPEN:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
    case SYS_FILESIZE:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
    case SYS_READ:
      if (!is_user_vaddr(&syscall_number[1]) || !is_user_vaddr(&syscall_number[2]) || !is_user_vaddr(&syscall_number[3]))
        exit (-1);
      break;
    case SYS_WRITE:
      if (!is_user_vaddr(&syscall_number[1]) || !is_user_vaddr(&syscall_number[2]) || !is_user_vaddr(&syscall_number[3]))
        exit (-1);
      f->eax = (uint32_t)write((int)syscall_number[1], (const void *)syscall_number[2], (unsigned)syscall_number[3]);
      break;
    case SYS_SEEK:
      if (!is_user_vaddr(&syscall_number[1]) || !is_user_vaddr(&syscall_number[2]))
        exit (-1);
      break;
    case SYS_TELL:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
    case SYS_CLOSE:
      if (!is_user_vaddr(&syscall_number[1]))
        exit (-1);
      break;
  }
  //printf ("system call!\n");
  //thread_exit ();
}

void memory_protection (void* address) {
  if (!is_user_vaddr(address)) {
    printf("exit!\n");
    exit (-1);
  }
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

int read (int fd, void *buffer, unsigned size) {
  int i;
    for (i = 0; i < size; i++) {
    	if (((char *)buffer)[i] == '\0') {
	  break;
	}
    }
}

int write (int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf((char *)buffer, size);
    return size;
  }
  return -1;
}
