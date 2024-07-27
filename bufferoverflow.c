#include <stdio.h>
#include <string.h>

int main(int argc,char *argv[]){
    char str[5];
    char str1[50];
    strcpy(argv[1],str);
    printf("%s\n",str);
    printf("%s",str1);
    return 0;
}