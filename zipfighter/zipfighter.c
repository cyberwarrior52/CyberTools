#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <zip.h>

#define HEAVY_TICK_SYMBOL "\u2714" // ✔

#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define UNDERLINE   "\033[4m"
#define REVERSED    "\033[7m"

#define BLACK       "\033[30m"
#define RED         "\033[31m" // for failure
#define GREEN       "\033[32m" // for success
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m" // for questions and related
#define MAGENTA     "\033[35m"
#define CYAN        "\033[36m"
#define WHITE       "\033[37m"

#define PASSWORD_SIZE 100
#define BUFFER_LEN_IN_ZIP_FILE 50
#define INTERNAL_BUFF 50

void Dashboard(){
    system("clear");
    printf("\n");
    printf(BOLD"$$$$$$$$\\ $$\\                 $$$$$$$$\\ $$\\           $$\\        $$\\                        \n"RESET);
    printf(BOLD"\\____$$  |\\__|                $$  _____|\\__|          $$ |       $$ |                       \n"RESET);
    printf(BOLD"    $$  / $$\\  $$$$$$\\        $$ |      $$\\  $$$$$$\\  $$$$$$$\\ $$$$$$\\    $$$$$$\\   $$$$$$\\ \n"RESET);
    printf(BOLD"   $$  /  $$ |$$  __$$\\       $$$$$$\\    $$ |$$  __$$\\ $$  __$$\\\\_$$  _|  $$  __$$\\ $$  __$$\\\n"RESET);
    printf(BOLD"  $$  /   $$ |$$ /  $$ |      $$  __|   $$ |$$ /  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \\__|\n"RESET);
    printf(BOLD" $$  /    $$ |$$ |  $$ |      $$ |      $$ |$$ |  $$ |$$ |  $$ | $$ |$$\\ $$   ____|$$ |       \n"RESET);
    printf(BOLD"$$$$$$$$\\ $$ |$$$$$$$  |      $$ |      $$ |\\$$$$$$$ |$$ |  $$ | \\$$$$  |\\$$$$$$$\\ $$ |       \n"RESET);
    printf(BOLD"\\________|\\__|$$  ____/       \\__|      \\__| \\____$$ |\\__|  \\__|  \\____/  \\_______|\\__|       \n"RESET);
    printf(BOLD"              $$ |                          $$\\   $$ |                                    \n"RESET);
    printf(BOLD"              $$ |                          \\$$$$$$  |                                    \n"RESET);
    printf(BOLD"              \\__|                           \\______/                                     \n"RESET);
    printf(BOLD"\t\t\t\t\t\t\t\t\t-by Mohamed hathim.\n"RESET);
    printf("\n");



}

void extract_zip_file(char *zip_file,char *internal_file,char *word_list) {
    FILE *file;
    int error;
    char password[PASSWORD_SIZE]; // Password to store the correct password
    zip_t *z_file;

    // Open the word list file
    file = fopen(word_list, "r");
    if (file == NULL) {
        perror(RED"Error opening word list file"RESET);
        exit(EXIT_FAILURE);
    }

    // Open the ZIP file
    z_file = zip_open(zip_file, ZIP_RDONLY, &error);
    if (z_file == NULL) {
        printf(RED "Can't open zip file. Error code: %d\n" RESET, error);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    while (fgets(password, sizeof(password), file) != NULL) {
        password[strcspn(password, "\r\n")] = '\0';

        // Attempt to open the file inside the ZIP with the current password
        struct zip_file *getpass = zip_fopen_encrypted(z_file, internal_file, ZIP_FL_UNCHANGED, password);
        if (getpass != NULL) {
            printf(GREEN HEAVY_TICK_SYMBOL " Password found: %s\n" RESET, password);
            zip_fclose(getpass);
            zip_close(z_file);
            fclose(file);
            return;
        }
    }

    printf(RED "Password not found\n" RESET);
    zip_close(z_file);
    fclose(file);
}

int main() {
    Dashboard();
    char file_name[BUFFER_LEN_IN_ZIP_FILE];
    char intern_name[INTERNAL_BUFF];
    char word_list[BUFFER_LEN_IN_ZIP_FILE];

    printf(BLUE "[+] Enter your zip file name : "RESET);
    scanf("%s",file_name);
    
    printf(BLUE "[+] Enter your first filename in this archive : "RESET);
    scanf("%s",intern_name);

    printf(BLUE "[+] Enter your wordlist file name : "RESET);
    scanf("%s",word_list);
    // Check if the file exists and is a .zip file
    if (access(file_name, F_OK) == 0 && strstr(file_name, ".zip") != NULL && access(word_list,F_OK) == 0) {
        printf(GREEN HEAVY_TICK_SYMBOL " These files are found and valid\n\n" RESET);
        sleep(1);
    } else {
        printf(RED "File not found or invalid file type\n" RESET);
        exit(EXIT_FAILURE);
    }
    extract_zip_file(file_name,intern_name,word_list);
    return 0;

}
