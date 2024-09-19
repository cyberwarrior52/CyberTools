#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_ADDR "127.0.0.1" // Adjust this to the VPN server's address
#define SERVER_PORT 6666
#define BUF_SIZE 1024

void handleErrors(void) {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "OpenSSL error: %s\n", err_buf);
    }
    abort();
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    struct sockaddr_in server_addr;
    char buffer[BUF_SIZE];
    int bytes;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL context\n");
        handleErrors();
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating SSL object\n");
        handleErrors();
    }

    // Create socket
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("socket");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(server);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(server, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(server);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Attach SSL to the socket
    SSL_set_fd(ssl, server);

    // Perform SSL/TLS handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed\n");
        handleErrors();
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Read data from the server
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes < 0) {
        fprintf(stderr, "SSL_read failed\n");
        handleErrors();
    } else {
        buffer[bytes] = '\0';
        printf("Received from server: %s\n", buffer);
    }

    // Clean up and close
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}
