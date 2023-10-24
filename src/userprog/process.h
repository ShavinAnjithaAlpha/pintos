#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

struct process_control_block
{
  pid_t pid;             // Process ID equal to thread ID
  struct list_elem elem; // List element for child processes list
  char *cmd_args;        // command line arguments pass to the program

  bool waiting;  // Is process being waited on
  bool exited;   // Has process exited
  int exit_code; // Exit code of process

  struct semaphore wait_sem; // semaphore for process waiting
  struct semaphore init_sem; // semaphore for process initialization
};

struct file_block
{
  int id;                // fd id
  struct list_elem elem; // list for open files
  struct file *file;     // file structure
};

pid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
