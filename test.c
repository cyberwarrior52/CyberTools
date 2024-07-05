#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char *argv[]){
    char of[2];

    if(strcmp(argv[1],"") == 0){
        printf("These are empty\n");
    } else {
        system(strcat("./",argv[1]));
    }

}
