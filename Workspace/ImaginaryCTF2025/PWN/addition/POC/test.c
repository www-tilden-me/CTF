#include <stdlib.h>
#include <stdio.h>

int main(){
	printf("Enter this %ld\n", 0x555555558020 - 0x00007fffffffd8c0);
	char buf[0x18];
	fgets(buf, 0x10, stdin);
	long i = atoll(buf);
	printf("Read: %ld = %lx\n", i, i);
	return 0;
}
