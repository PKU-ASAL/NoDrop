#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[], char *env[])
{
    // if (argc > 0)
    //     puts(argv[0]);
    char path[10];
    sprintf(path, "%d.txt", getpid());
    FILE *file = fopen(path, "a");
    if (argc > 0 && file)
        fprintf(file, "monitor: %s\n", argv[0]);
    fclose(file); 
    return 0;
}