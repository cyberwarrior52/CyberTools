#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <minizip/unzip.h>

#define WORD_LIST "word_list.txt"
#define MAX_PASSWORD_LENGTH 100

// Function to extract a file from the ZIP archive using a password
int extract_file_with_password(const char *zip_file_name, const char *password) {
    unzFile zip_file;
    int result;

    // Open the ZIP file
    zip_file = unzOpen(zip_file_name);
    if (zip_file == NULL) {
        perror("Error opening ZIP file");
        return -1;
    }

    // Go to the first file in the ZIP archive
    if (unzGoToFirstFile(zip_file) != UNZ_OK) {
        perror("Error going to the first file in the ZIP archive");
        unzClose(zip_file);
        return -1;
    }

    // Try to open the current file with the password
    result = unzOpenCurrentFilePassword(zip_file, password);
    if (result == UNZ_OK) {
        // Successfully opened the file, so the password is correct
        unzCloseCurrentFile(zip_file);
        unzClose(zip_file);
        return 0;
    } else {
        // Password is incorrect
        unzCloseCurrentFile(zip_file);
        unzClose(zip_file);
        return -1;
    }
}

// Function to read passwords from a word list and test them
void crack_zip_password(const char *zip_file_name) {
    FILE *word_list;
    char password[MAX_PASSWORD_LENGTH];
    int found = 0;

    word_list = fopen(WORD_LIST, "r");
    if (word_list == NULL) {
        perror("Error opening word list file");
        return;
    }

    printf("Start cracking...\n");

    // Try each password from the word list
    while (fgets(password, sizeof(password), word_list) != NULL) {
        // Remove newline character from the end of the line
        password[strcspn(password, "\r\n")] = '\0';

        // Try to extract the file with the current password
        if (extract_file_with_password(zip_file_name, password) == 0) {
            printf("Password found: %s\n", password);
            found = 1;
            break;
        } else {
            printf("Trying password: %s\n", password);
        }
    }

    if (!found) {
        printf("Password not found in the word list file.\n");
    }

    fclose(word_list);
}

int main() {
    char zip_file_name[100];

    printf("Enter path of the zip file: ");
    if (scanf("%99s", zip_file_name) != 1) {
        fprintf(stderr, "Error reading input.\n");
        return EXIT_FAILURE;
    }

    // Check if the file exists
    if (access(zip_file_name, F_OK) != 0) {
        perror("File error");
        return EXIT_FAILURE;
    }

    // Start cracking the ZIP file password
    crack_zip_password(zip_file_name);

    return EXIT_SUCCESS;
}
