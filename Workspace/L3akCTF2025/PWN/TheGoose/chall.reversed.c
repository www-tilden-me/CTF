#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

char username[65];  // assuming this is global
int nhonks;

int64_t setuser() {
    puts("Welcome to the goose game.\nHere...");
    printf("How shall we call you?\n> ");
    return scanf("%64s", username);
}

uint64_t guess() {
    int guess = 0;

    printf("\n...\n\nso %s, how many honks?", username);
    scanf("%d", &guess);
    putchar('\n');

    for (int i = 0; i < nhonks; i++)
        printf(" HONK ");
    
    putchar('\n');
    return guess == nhonks;
}

int64_t highscore() {
    char formatted[0x50];
    char name[0x20];
    char msg[0x100];

    strcpy(formatted, "wow %s you're so good. what message would you like to leave to the world?");
    
    printf("what's your name again? ");
    scanf("%31s", name);
    printf("formatted: %p\n", &formatted);
    printf("msg: %p\n", &msg);

    sprintf(msg, formatted, name);
    printf(msg);  // format string vulnerability

    read(0, msg, 0x400);  //buffer overflow

    return printf("got it. bye now.\n");
}

int32_t main(int argc, char** argv, char** envp) {
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(time(NULL));

    setuser();
    nhonks = rand() % 0x5b + 0xa;  // nhonks = 10 to 100

    if (!guess()) {
        puts("Tough luck. THE GOOSE WINS! GET HONKED.");
    } else {
        highscore();
    }

    return 0;
}
