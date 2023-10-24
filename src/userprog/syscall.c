#include "userprog/syscall.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

static void handle_invalid_access (void);
static struct file_desc *find_file_desc (int fd);
static bool put_user (uint8_t *udst, uint8_t byte);
static int get_user (const uint8_t *uaddr);
static int mem_read (void *src, void *dest, size_t bytes);
static void read_from_stack (struct intr_frame *f, void *dest, int ind);

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *filename, unsigned initial_size);
bool sys_remove (const char *filename);
int sys_open (const char *filename);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

struct lock filesys_lock;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;

  /* Get system call number */
  read_from_stack (f, &syscall_number, 0);

  switch (syscall_number)
  {
  case SYS_HALT:
    {
      sys_halt ();
      break;
    }
  case SYS_EXIT:
    {
      int exit_code;
      read_from_stack (f, &exit_code, 1);

      sys_exit (exit_code);
      NOT_REACHED ();
      break;
    }
  case SYS_EXEC:
    {
      void *cmd_line;
      read_from_stack (f, &cmd_line, 1);

      f->eax = (uint32_t) sys_exec ((const char*) cmd_line);
      break;
    }
  case SYS_WAIT:
    {
      pid_t pid;
      read_from_stack (f, &pid, 1);

      f->eax = (uint32_t) sys_wait (pid);
      break;
    }
  case SYS_CREATE:
    {
      char *filename;
      unsigned initial_size;
      read_from_stack (f, &filename, 1);
      read_from_stack (f, &initial_size, 2);

      f->eax = (uint32_t) sys_create (filename, initial_size);
      break;
    }
  case SYS_REMOVE:
    {
      char *filename;
      read_from_stack (f, &filename, 1);

      f->eax = (uint32_t) sys_remove (filename);
      break;
    }
  case SYS_OPEN:
    {
      char *filename;
      read_from_stack (f, &filename, 1);

      f->eax = (uint32_t) sys_open (filename);
      break;
    }
  case SYS_FILESIZE:
    {
      int fd;
      read_from_stack (f, &fd, 1);

      f->eax = (uint32_t) sys_filesize (fd);
      break;
    }
  case SYS_READ:
    {
      int fd;
      void *buffer;
      unsigned size;
      read_from_stack (f, &fd, 1);
      read_from_stack (f, &buffer, 2);
      read_from_stack (f, &size, 3);

      f->eax = (uint32_t) sys_read (fd, buffer, size);
      break;
    }
  case SYS_WRITE:
    {
      int fd, return_code;
      void *buffer;
      unsigned int size;
      read_from_stack (f, &fd, 1);
      read_from_stack (f, &buffer, 2);
      read_from_stack (f, &size, 3);

      f->eax = (uint32_t) sys_write (fd, buffer, size);
      break;
    }
  case SYS_SEEK:
    {
      int fd;
      unsigned position;
      read_from_stack (f, &fd, 1);
      read_from_stack (f, &position, 2);

      sys_seek (fd, position);
      break;
    }
  case SYS_TELL:
    {
      int fd;
      read_from_stack (f, &fd, 1);

      f->eax = (uint32_t) sys_tell (fd);
      break;
    }
  case SYS_CLOSE:
    {
      int fd;
      read_from_stack (f, &fd, 1);

      sys_close (fd);
      break;
    }
  default:
    printf ("[ERROR]: system call %d is unimplemented\n", syscall_number);
    sys_exit (-1);
    break;
  }
}

void
sys_halt (void)
{
  shutdown_power_off ();
  NOT_REACHED ();
}

static void
handle_invalid_access (void)
{
  if (lock_held_by_current_thread (&filesys_lock))
    lock_release (&filesys_lock);
  sys_exit (-1);
  NOT_REACHED ();
}

void
sys_exit (int status)
{
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  struct process_control_block *pcb = thread_current ()->pcb;
  pcb->exited = true;
  pcb->exit_code = status;
  sema_up (&pcb->waiting_sema);
  thread_exit ();
}

/* Runs command CMD_LINE.
   Returns tid of child thread if successful, -1 if a
   segfault occurs. */
pid_t
sys_exec (const char *cmd_line)
{
  if (get_user ((const uint8_t *) cmd_line) == -1)
    handle_invalid_access ();

  /* Check validity of cmd_line string */
  int i = 0;
  while (true)
    {
      char temp = get_user ((const uint8_t *) (cmd_line + i));
      if (temp == -1)  /* Invalid memory */
        {
          handle_invalid_access ();
        }
      else if (temp == 0)  /* Null terminator */
        break;
      i++;
    }

  lock_acquire (&filesys_lock);
  pid_t pid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return pid;
}

int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

bool
sys_create (const char *filename, unsigned initial_size)
{
  if (get_user (filename) == -1)
    handle_invalid_access ();

  lock_acquire (&filesys_lock);
  bool return_value = filesys_create (filename, initial_size);
  lock_release (&filesys_lock);
  return return_value;
}

bool
sys_remove (const char *filename)
{
  if (get_user (filename) == -1)
    handle_invalid_access ();

  lock_acquire (&filesys_lock);
  bool return_value = filesys_remove (filename);
  lock_release (&filesys_lock);
  return return_value;
}

int
sys_open (const char *filename)
{
  struct file *opened_file;
  struct file_desc *f_desc;
  if (get_user (filename) == -1)
    handle_invalid_access ();

  lock_acquire (&filesys_lock);
  opened_file = filesys_open (filename);
  if (!opened_file)
    {
      lock_release (&filesys_lock);
      return -1;
    }

  f_desc = malloc (sizeof (*f_desc));
  f_desc->file = opened_file;
  struct list *files_list = &thread_current ()->file_descriptors;
  if (list_empty (files_list))
    f_desc->id = 2; /* 0=STDIN, 1=STDOUT */
  else
    f_desc->id = list_entry (list_back (files_list), struct file_desc, elem)->id + 1;
  list_push_back (files_list, &f_desc->elem);
  lock_release (&filesys_lock);

  return f_desc->id;
}

int
sys_filesize (int fd)
{
  struct file_desc *f_desc = find_file_desc (fd);

  if (f_desc == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  int length = file_length (f_desc->file);
  lock_release (&filesys_lock);
  return length;
}

int
sys_read (int fd, void *buffer, unsigned size)
{
  if (get_user ((const uint8_t *) buffer) == -1)
    handle_invalid_access ();

  if (fd == 0)
    {  // STDIN
      for (int i = 0; i < size; i++)
        if (!put_user (buffer + i, input_getc ()))
          handle_invalid_access ();
      return size;
    }
  else
    {
      lock_acquire (&filesys_lock);
      struct file_desc *f_desc = find_file_desc (fd);

      if (f_desc && f_desc->file)
        {
          off_t bytes_read = file_read (f_desc->file, buffer, size);
          lock_release (&filesys_lock);
          return bytes_read;
        }
      else
        {
          lock_release (&filesys_lock);
          return -1;
        }
    }
}

int
sys_write (int fd, const void *buffer, unsigned size)
{
  if (get_user ((const uint8_t *) buffer) == -1)
    handle_invalid_access ();

  if (fd == 1)
    {
      putbuf ((const char*) buffer, size);
      return size;
    }
  else
    {
      lock_acquire (&filesys_lock);
      struct file_desc *f_desc = find_file_desc (fd);

      if (f_desc && f_desc->file)
        {
          off_t bytes_written = file_write (f_desc->file, buffer, size);
          lock_release (&filesys_lock);
          return bytes_written;
        }
      else
        {
          lock_release (&filesys_lock);
          return -1;
        }
    }
}

void
sys_seek (int fd, unsigned position)
{
  lock_acquire (&filesys_lock);
  struct file_desc *f_desc = find_file_desc (fd);

  if (f_desc && f_desc->file)
    {
      file_seek (f_desc->file, position);
      lock_release (&filesys_lock);
    }
  else
    {
      lock_release (&filesys_lock);
      sys_exit (-1);
    }
}

unsigned
sys_tell (int fd)
{
  lock_acquire (&filesys_lock);
  struct file_desc *f_desc = find_file_desc (fd);

  if (f_desc && f_desc->file)
    {
      off_t pos = file_tell (f_desc->file);
      lock_release (&filesys_lock);
      return pos;
    }
  else
    {
      lock_release (&filesys_lock);
      sys_exit (-1);
    }
}

void
sys_close (int fd)
{
  lock_acquire (&filesys_lock);
  struct file_desc *f_desc = find_file_desc (fd);

  if (f_desc && f_desc->file)
    {
      file_close (f_desc->file);
      list_remove (&f_desc->elem);
      free (f_desc);
    }
  lock_release (&filesys_lock);
}

static struct file_desc*
find_file_desc (int fd)
{
  if (fd < 2)
    return NULL;

  struct thread *t = thread_current ();

  if (list_empty (&t->file_descriptors))
    return NULL;

  struct list_elem *e;
  struct file_desc *result = NULL;
  for (e = list_begin (&t->file_descriptors); e != list_end (&t->file_descriptors);
       e = list_next (e))
    {
      struct file_desc *f_desc =
        list_entry (e, struct file_desc, elem);
      if (f_desc->id == fd)
        {
          result = f_desc;
          break;
        }
    }
  return result;
}

/* Read IND argument from stack pointer in F and store at DEST. */
static void
read_from_stack (struct intr_frame *f, void *dest, int ind)
{
  mem_read (f->esp + ind * 4, dest, 4);
}

/* Reads BYTES bytes at SRC and stores at DEST.
   Returns number of bytes read if successful, -1 if a
   segfault occurred. */
static int
mem_read (void *src, void *dest, size_t bytes)
{
  int32_t value;
  for (size_t i = 0; i < bytes; i++)
    {
      value = get_user (src + i);
      if (value == -1)
        handle_invalid_access ();
      *(char*)(dest + i) = value;
    }
  return (int)bytes;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if ((void*)uaddr >= PHYS_BASE)
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if ((void*)udst >= PHYS_BASE)
    return false;

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
