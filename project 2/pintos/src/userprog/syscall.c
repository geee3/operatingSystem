#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);

struct file {
  struct inode *inode;
  off_t pos;
  bool cannot_write;
};

struct lock wrt_lock;
struct lock mutex;
int read_counter = 0;

void
syscall_init (void) 
{
  lock_init(&wrt_lock);
  lock_init(&mutex);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *system_call = f->esp;
  if (!is_user_vaddr(system_call))
    exit(-1);

  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      memory_protection(system_call, 1);
      exit(system_call[1]);
      break;
    case SYS_EXEC:
      memory_protection(system_call, 1);
      f->eax = (uint32_t)exec((const char *)system_call[1]);
      break;
    case SYS_WAIT:
      memory_protection(system_call, 1);
      f->eax = (uint32_t)wait((pid_t)system_call[1]);
      break;
    case SYS_CREATE:
      memory_protection(system_call, 2);
      f->eax = (uint32_t)create((const char *)system_call[1], (unsigned)system_call[2]);
      break;
    case SYS_REMOVE:
      memory_protection(system_call, 1);
      f->eax = (uint32_t)remove((const char *)system_call[1]);
      break;
    case SYS_OPEN:
      memory_protection(system_call, 1);
      f->eax = (uint32_t)open((const char *)system_call[1]);
      break;
    case SYS_FILESIZE:
      memory_protection(system_call, 1);
      f->eax = (uint32_t)filesize((int)system_call[1]);
      break;
    case SYS_READ:
      memory_protection(system_call, 3);
      f->eax = (uint32_t)read((int)system_call[1], (void *)system_call[2], (unsigned)system_call[3]);
      break;
    case SYS_WRITE:
      memory_protection(system_call, 3);
      f->eax = (uint32_t)write((int)system_call[1], (const void *)system_call[2], (unsigned)system_call[3]);
      break;
    case SYS_SEEK:
      memory_protection(system_call, 2);
      seek((int)system_call[1], (unsigned)system_call[2]);
      break;
    case SYS_TELL:
      memory_protection(system_call, 1);
      f->eax = tell((int)system_call[1]);
      break;
    case SYS_CLOSE:
      memory_protection(system_call, 1);
      close((int)system_call[1]);
      break;
  } 
  //printf ("system call!\n");
  //thread_exit ();
}

void memory_protection (int* address, int range) {
  for (int i = 1; i <= range; i++) {
    if (!is_kernel_vaddr(&address[i]))
      exit(-1);
  }
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", thread_name(), status);
  t->exit_status = status;

  for (int i = 3; i < 128; i++) {
    if (t->fd[i] != NULL)
      close(i);
  }
  thread_exit();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  if (file == NULL)
    exit(-1);
  return filesys_create(file, initial_size);
}

bool remove (const char *file) {
  if (file == NULL)
    exit(-1);
  return filesys_remove(file);
}

int open (const char *file) {
  struct thread *t = thread_current();
  struct file *f;
  int i, state = 0;

  if (file == NULL)
    exit(-1);
  lock_acquire(&wrt_lock);

  f = filesys_open(file);
  if (f) {
    for (i = 3; i < 128; i++) {
      if (t->fd[i] == NULL) {
        state = i;
	t->fd[i] = f;

	if (!strcmp(file, thread_name()))
          file_deny_write(f);
	break;
      }
    }
  }
  else
    state = -1;
  lock_release(&wrt_lock);
  return state;
}

int filesize (int fd) {
  return file_length(thread_current()->fd[fd]);
}

int read (int fd, void *buffer, unsigned size) {
  int i, pointer = -1;

  if (buffer == NULL)
    exit(-1);
  if (!is_user_vaddr(buffer))
    exit(-1);

  lock_acquire(&mutex);
  read_counter += 1;

  if (read_counter == 1)
    lock_acquire(&wrt_lock);
  
  if (fd == 0) {
    for (i = 0; i < (int)size; i++) {
      ((uint8_t *)buffer)[i] = input_getc();
      if (((uint8_t *)buffer)[i] == 0)
        break;
    }
    read_counter -= 1;
    if (read_counter == 0)
      lock_release(&wrt_lock);
    lock_release(&mutex);
    return i;
  }
  else if (fd >= 3 && thread_current()->fd[fd]) {
    pointer = file_read(thread_current()->fd[fd], buffer, size);
  }
  
  read_counter -= 1;
  if (read_counter == 0)
    lock_release(&mutex);
  if (fd >= 3 && pointer == -1)
    exit(-1);
  return pointer;
}

int write (int fd, const void *buffer, unsigned size) {
  int pointer = -1;
  if (buffer == NULL)
    exit(-1);
  if (!is_user_vaddr(buffer))
    exit(-1);
  lock_acquire(&wrt_lock);

  if (fd == 1) {
    putbuf(buffer, size);
    pointer = size;
  }
  else if (fd > 2 && thread_current()->fd[fd]) {
    if (thread_current()->fd[fd]->cannot_write)
      file_deny_write(thread_current()->fd[fd]);
    pointer = file_write(thread_current()->fd[fd], buffer, size);
  }

  lock_release(&wrt_lock);
  if (pointer == -1)
    exit(-1);
  return pointer;
}

void seek (int fd, unsigned position) {
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  thread_current()->fd[fd] = NULL;
  file_close(f);
}
