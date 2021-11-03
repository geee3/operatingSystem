#include "userprog/syscall.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      memory_protection(f->esp + 4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      memory_protection(f->esp + 4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      memory_protection(f->esp + 4);
      f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      memory_protection(f->esp + 20);
      memory_protection(f->esp + 24);
      memory_protection(f->esp + 28);
      f->eax = read((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;
    case SYS_WRITE:
      memory_protection(f->esp + 20);
      memory_protection(f->esp + 24);
      memory_protection(f->esp + 28);
      f->eax = write((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
  } 
  //printf ("system call!\n");
  //thread_exit ();
}

void memory_protection (const void* address) {
  if (is_kernel_vaddr(address))
    exit(-1);
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
  uint32_t i;
  if (fd == 0) {
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = (char)input_getc();
      if (((char *)buffer)[i] == '\0')
	break;
    }
    return i;
  }
  return size;
}

int write (int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf((char *)buffer, size);
    return size;
  }
  return -1;
}
