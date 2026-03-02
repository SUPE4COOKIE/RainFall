#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char flag[] = "579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245";
    char *input = "";
    int intput = atoi(input);

    flag[intput] = '\0';
    printf("%d" ,strcmp(flag, input));

    return 0;
}