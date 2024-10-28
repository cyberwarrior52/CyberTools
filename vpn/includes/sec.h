#include <string.h>

int IllegalCharFinder(char *str){
    for(int i = 0;i < strlen(str);i++){
        switch(str[i]){
            case ';':
            return 0;
            break;

            case ':':
            return 0;
            break;

            case '@':
            return 0;
            break;

            case '%':
            return 0;
            break;

            case '&':
            return 0;
            break;
        }
    }
    return 1;
}