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

static void syscall_handler(struct intr_frame *);

static void invalid_access_hanlder(void);
static struct file_block *find_file_desc(int fd);
static bool put_user(uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
static int stack_read(void *src, void *dest, size_t bytes);

void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *filename, unsigned initial_size);
bool sys_remove(const char *filename);
int sys_open(const char *filename);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

struct lock filesystem_lock;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesystem_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall_id;

  // get the sustem call ID from the stack
  read_stack(f, &syscall_id, 0);

  // based on the syscall ID, call the appropriate syscall
  switch (syscall_id)
  {
  case SYS_HALT:
  {
    sys_halt();
    break;
  }
  case SYS_EXIT:
  {
    int exit_code;
    stack_read(f->esp + 4, &exit_code, 4);

    sys_exit(exit_code);
    NOT_REACHED();
    break;
  }
  case SYS_EXEC:
  {
    void *cmd_line;
    stack_read(f->esp + 4, &cmd_line, 4);

    f->eax = (uint32_t)sys_exec((const char *)cmd_line);
    break;
  }
  case SYS_WAIT:
  {
    pid_t pid;
    stack_read(f->esp + 4, &pid, 4);

    f->eax = (uint32_t)sys_wait(pid);
    break;
  }
  case SYS_CREATE:
  {
    char *file_name;
    unsigned initial_size;
    stack_read(f->esp + 4, &file_name, 4);
    stack_read(f->esp + 8, &initial_size, 4);

    f->eax = (uint32_t)sys_create(file_name, initial_size);
    break;
  }
  case SYS_REMOVE:
  {
    char *filename;
    stack_read(f->esp + 4, &filename, 4);

    f->eax = (uint32_t)sys_remove(filename);
    break;
  }
  case SYS_OPEN:
  {
    char *filename;
    stack_read(f->esp + 4, &filename, 4);

    f->eax = (uint32_t)sys_open(filename);
    break;
  }
  case SYS_FILESIZE:
  {
    int fd;
    stack_read(f->esp + 4, &fd, 4);

    f->eax = (uint32_t)sys_filesize(fd);
    break;
  }
  case SYS_READ:
  {
    int fd;
    void *buffer;
    unsigned size;
    stack_read(f->esp + 4, &fd, 4);
    stack_read(f->esp + 8, &buffer, 4);
    stack_read(f->esp + 12, &size, 4);
    read_stack(f, &size, 3);

    f->eax = (uint32_t)sys_read(fd, buffer, size);
    break;
  }
  case SYS_WRITE:
  {
    int fd, return_code;
    void *buffer;
    unsigned int size;
    stack_read(f->esp + 4, &fd, 4);
    stack_read(f->esp + 8, &buffer, 4);
    stack_read(f->esp + 12, &size, 4);

    f->eax = (uint32_t)sys_write(fd, buffer, size);
    break;
  }
  case SYS_SEEK:
  {
    int fd;
    unsigned position;
    stack_read(f->esp + 4, &fd, 4);
    stack_read(f->esp + 8, &position, 4);

    sys_seek(fd, position);
    break;
  }
  case SYS_TELL:
  {
    int fd;
    stack_read(f->esp + 4, &fd, 4);
    f->eax = (uint32_t)sys_tell(fd);
    break;
  }
  case SYS_CLOSE:
  {
    int fd;
    stack_read(f->esp + 4, &fd, 4);
    sys_close(fd);
    break;
  }
  default:
    printf("Invalid syscall number: %d\n", syscall_id);
    sys_exit(-1);
    break;
  }
}

static void
invalid_access_hanlder(void)
{
  if (lock_held_by_current_thread(&filesystem_lock))
    lock_release(&filesystem_lock);
  sys_exit(-1);
  NOT_REACHED();
}

void sys_halt(void)
{
  shutdown_power_off();
  NOT_REACHED();
}

void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  struct process_control_block *pcb = thread_current()->pcb;
  pcb->exited = true;
  pcb->exit_code = status;
  sema_up(&pcb->wait_sem);
  thread_exit();
}

// execute the command line and return the pid of the new process
pid_t sys_exec(const char *cmd_line)
{
  if (get_user((const uint8_t *)cmd_line) == -1)
    invalid_access_hanlder();

  /* Check validity of cmd_line string */
  int i = 0;
  while (true)
  {
    char tmp = get_user((const uint8_t *)(cmd_line + i));
    if (tmp == -1) /* Invalid memory */
    {
      invalid_access_hanlder();
    }
    else if (tmp == 0) /* Null terminator */
      break;
    i++;
  }

  lock_acquire(&filesystem_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesystem_lock);
  return pid;
}

int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

bool sys_create(const char *filename, unsigned initial_size)
{
  if (get_user(filename) == -1)
    invalid_access_hanlder();

  lock_acquire(&filesystem_lock);
  bool ret = filesys_create(filename, initial_size);
  lock_release(&filesystem_lock);
  return ret;
}

bool sys_remove(const char *filename)
{
  if (get_user(filename) == -1)
    invalid_access_hanlder();

  lock_acquire(&filesystem_lock);
  bool return_value = filesys_remove(filename);
  lock_release(&filesystem_lock);
  return return_value;
}

int sys_open(const char *filename)
{
  struct file *opened_file;
  struct file_block *f_desc;
  if (get_user(filename) == -1)
    invalid_access_hanlder();

  lock_acquire(&filesystem_lock);
  opened_file = filesys_open(filename);
  if (!opened_file)
  {
    lock_release(&filesystem_lock);
    return -1;
  }

  f_desc = malloc(sizeof(*f_desc));
  f_desc->file = opened_file;
  struct list *files_list = &thread_current()->file_descriptors;
  if (list_empty(files_list))
    f_desc->id = 2; /* 0=STDIN, 1=STDOUT */
  else
    f_desc->id = list_entry(list_back(files_list), struct file_desc, elem)->id + 1;
  list_push_back(files_list, &f_desc->elem);
  lock_release(&filesystem_lock);

  return f_desc->id;
}

int sys_filesize(int fd)
{
  struct file_block *f_desc = find_file_desc(fd);

  if (f_desc == NULL)
    return -1;

  lock_acquire(&filesystem_lock);
  int length = file_length(f_desc->file);
  lock_release(&filesystem_lock);
  return length;
}

int sys_read(int fd, void *buffer, unsigned size)
{
  if (get_user((const uint8_t *)buffer) == -1)
    invalid_access_hanlder();

  if (fd == 0)
  {
    for (int i = 0; i < size; i++)
      if (!put_user(buffer + i, input_getc()))
        invalid_access_hanlder();
    return size;
  }
  else
  {
    lock_acquire(&filesystem_lock);
    struct file_block *f_desc = find_file_desc(fd);

    if (f_desc && f_desc->file)
    {
      off_t bytes_read = file_read(f_desc->file, buffer, size);
      lock_release(&filesystem_lock);
      return bytes_read;
    }
    else
    {
      lock_release(&filesystem_lock);
      return -1;
    }
  }
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  if (get_user((const uint8_t *)buffer) == -1)
    invalid_access_hanlder();

  if (fd == 1)
  {
    putbuf((const char *)buffer, size);
    return size;
  }
  else
  {
    lock_acquire(&filesystem_lock);
    struct file_block *f_desc = find_file_desc(fd);

    if (f_desc && f_desc->file)
    {
      off_t bytes = file_write(f_desc->file, buffer, size);
      lock_release(&filesystem_lock);
      return bytes;
    }
    else
    {
      lock_release(&filesystem_lock);
      return -1;
    }
  }
}

void sys_seek(int fd, unsigned position)
{
  lock_acquire(&filesystem_lock);
  struct file_block *f_desc = find_file_desc(fd);

  if (f_desc && f_desc->file)
  {
    file_seek(f_desc->file, position);
    lock_release(&filesystem_lock);
  }
  else
  {
    lock_release(&filesystem_lock);
    sys_exit(-1);
  }
}

unsigned
sys_tell(int fd)
{
  lock_acquire(&filesystem_lock);
  struct file_block *f_desc = find_file_desc(fd);

  if (f_desc && f_desc->file)
  {
    off_t pos = file_tell(f_desc->file);
    lock_release(&filesystem_lock);
    return pos;
  }
  else
  {
    lock_release(&filesystem_lock);
    sys_exit(-1);
  }
}

void sys_close(int fd)
{
  lock_acquire(&filesystem_lock);
  struct file_block *f_desc = find_file_desc(fd);

  if (f_desc && f_desc->file)
  {
    file_close(f_desc->file);
    list_remove(&f_desc->elem);
    free(f_desc);
  }
  lock_release(&filesystem_lock);
}

// end of syscall handlers

static struct file_block *
find_file_desc(int fd)
{
  if (fd < 2)
    return NULL;

  struct thread *t = thread_current(); // get current thread

  if (list_empty(&t->file_descriptors)) // if the list is empty, return NULL
    return NULL;

  struct list_elem *e;
  struct file_block *result = NULL;
  for (e = list_begin(&t->file_descriptors); e != list_end(&t->file_descriptors); // iterate through the list
       e = list_next(e))
  {
    struct file_block *f_desc =
        list_entry(e, struct file_block, elem); // get the file descriptor from the list
    if (f_desc->id == fd)
    {
      result = f_desc;
      break;
    }
  }
  return result;
}

// read bytes from src to dest and return the number of bytes read
static int
stack_read(void *src, void *dest, size_t bytes)
{
  int32_t value;
  size_t i;
  for (i = 0; i < bytes; i++)
  {
    value = get_user(src + i);
    if (value == -1)
      invalid_access_hanlder();
    *(char *)(dest + i) = value;
  }
  return (int)bytes;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
  if ((void *)uaddr >= PHYS_BASE)
    return -1;

  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  if ((void *)udst >= PHYS_BASE)
    return false;

  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}
