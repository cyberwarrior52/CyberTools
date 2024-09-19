#include <stdio.h>
#include <termios.h>
#include <unistd.h>

void disableEcho() {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ECHO;  // Disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void enableEcho() {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag |= ECHO;  // Enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int main() {
    char password[100];
    int i = 0;

    printf("Enter your password: ");
    
    disableEcho();  // Turn off echo

    while (1) {
        char ch = getchar();
        if (ch == '\n' || ch == '\r') {
            break;
        }
        if (i < sizeof(password) - 1) {
            password[i++] = ch;
            printf("*");  // Print '*' for each character entered
        }
    }

    password[i] = '\0';  // Null-terminate the password

    enableEcho();  // Turn on echo

    printf("\nYour password is: %s\n", password);

    return 0;
}
