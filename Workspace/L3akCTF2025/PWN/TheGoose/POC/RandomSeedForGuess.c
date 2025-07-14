#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
	srand(time(NULL));
	int nhonks = rand() % 0x5b + 0xa;

	puts("Guess the number: ");
	int guess;
	scanf("%d", &guess);

	if (guess == nhonks){
		printf("Yes. You guess %d and it WAS %d", guess, nhonks);
	} else {
		printf("No. You guess %d and it was %d", guess, nhonks);
	}
	return 0;
}
