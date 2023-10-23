#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

// ------------------------------------------------------------------------------------
typedef int pid_t;

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

// get the argumnets from the user's stack
void get_stack_args (struct intr_frame *f, int *args, int num_of_args);
// ensure that a given address in in valid memory area
void is_valid (const void *ptr);

/* Ensures that each memory address in a given buffer is in valid user space. */
void check_buffer (void *buff, unsigned size);

struct lock lock_filesys;

// ------------------------------------------------------------------------------------

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();

  is_valid((const void *) f->esp);

  // stack argumnets buffer
  int args[3];

  // get the syscall number from the user stack
  int syscall_num = *(int *) f->esp;

  switch (syscall_num)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }

    case SYS_EXIT:
    {
      break;
    }

    case SYS_EXEC: 
    {
      break;
    }

    case SYS_WAIT:
    {
      break;
    }

    case SYS_CREATE:
    {
      break;
    }

    case SYS_REMOVE:
    {
      break;
    }

    case SYS_OPEN:
    {
      break;
    }

    case SYS_FILESIZE:
    {
      break;
    }

    case SYS_READ:
    {
      break;
    }

    case SYS_WRITE:
    {
      break;
    }

    case SYS_SEEK:
    {
      break;
    }

    case SYS_TELL:
    {
      break;
    }

    case SYS_CLOSE:{
      break;
    }

    default:
      exit(-1);
      break;
  }
}


// halt sys call handler -- shutdown the system
static void
halt(void)
{
  shutdown_power_off();
}

// exit system call handler -- exit the currenly running thread by setting the exit status
static void 
exit (int status)
{
  thread_current()->exit_status = status; // set the current running thread exit status
  printf("%s: exit(%d)\n", thread_current()->name, status); // print the program's name and its status on the terminal
  thread_exit(); // exit from the thread
}

// wait system call handler -- simply pass the control to the process's wait function
static void 
wait(pid_t pid)
{
  return process_wait(pid);
}

// file create sys call handler -- create a file in the file system with given name and initial size
static bool
create(const char *file_name, unsigned initial_size)
{
  lock_acquire(&lock_filesys); // acquire the file system lock
  bool file_status = filesys_create(file_name, initial_size); // create the file name with given arguments
  lock_release(&lock_filesys); // release the lock
  return file_status;
}

// file remove sys call handler -- remove a file from the file system 
static bool
remove(const char* file_name)
{
  lock_acquire(&lock_filesys); // acquire the file system lock
  bool file_status = filesys_remove(file_name); // create the file name with given arguments
  lock_release(&lock_filesys); // release the lock
  return file_status;
}


static int 
open(const char* file_name)
{
  lock_acquire(&lock_filesys);
  struct file *file_ = filesys_open(file_name);

  if (file_ == NULL)
  {
    lock_release(&lock_filesys);
    return -1;
  }

  
}







// ------------------------------------------- utility functions -------------------------------

void get_stack_args (struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      is_valid((const void *) ptr);
      args[i] = *ptr;
    }
}

void is_valid (const void *ptr)
{
  
  if(!is_user_vaddr(ptr) || ptr == NULL || ptr < (void *) 0x08048000)
	{
    // Terminate the program and free its resource
    exit(-1);
	}
}


void check_buffer (void *buff, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff;
  for (i = 0; i < size; i++)
    {
      is_valid((const void *) ptr);
      ptr++;
    }
}


