/*
In highscore there is a read vulnerability as seen below

```
lea    -0x170(%rbp),%rax
mov    $0x400,%edx
mov    %rax,%rsi
mov    $0x0,%edi
mov    $0x0,%eax
call   1060 <read@plt>
```

We will make this exactly -- without the constraints of getting there and with the theory that we have gotten the stack address that we need
*/

#include <stdio.h>
#include <unistd.h>

int main(){
	char buf[0x170];

	printf("buf is at: %p\n", &buf);

	puts("Now reading in\n >>>");
	fflush(stdout);
	read(0, buf, 0x400);
}