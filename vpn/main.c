#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <termios.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <mysql/mysql.h>
#include "protos.h"

//This global variable for create sql environment.
MYSQL *connection;

/**
 * Make a vpn to capture network packets via tcp/ip from the network interface
 * 
 * 1.Make a function to capture the each packets.
 * 
 * 2.Make a firewall to capture each packets as safely and encrypted and decrypted.
 * 
 *                                  SESSION
 * Manage session to on and off vpn server and which is make safely for users.set session
 * id to get the each users are use our server or invalid! and make it secure by SSL
 * 
*/

/**                                 DOCS FOR NEW USERS
 * if we are new user,the user cam should create and enter this vpn server and other furthur process.
 * this tool should will be update on future.so this credentials is more important things
 * 
 * if its not for at this time but should we'll make a proccess using that users credentials.
*/

void clearscn(){
    system("clear");
}

/**
 * the log_account() has two arguments that's name,password to find the user already create a account or not.
 * if the user credentials are match in this name and password, the user have a account in this vpn account.
*/

int log_account(char *u_name, char *u_password){
    connection = mysql_init(NULL); // establish a database connection for fetch data for checking.
    MYSQL_RES *result;
    MYSQL_ROW fetch_row;

    // Initialization of SQL database server.
    if (connection == NULL)  
        fprintf(stderr,"%s",mysql_error(connection));

    // Get database connection parameters from file
    const char *db_server = "localhost";
    const char *db_user = "root";
    const char *db_password = "mohamed";
    const char *database_name = "vpn";

    // Connect to the database
    if (mysql_real_connect(connection, db_server, db_user, db_password, database_name, DB_PORT, NULL, 0) == NULL) {
        fprintf(stderr, "Connection failed: %s\n", mysql_error(connection));
        mysql_close(connection);
        exit(EXIT_FAILURE);
    } else {
        printf(GREEN BOLD"DB server status : SUCCESS\n"RESET);
    }
    // Prepare query string safely
    char query[200];
    strcpy(query,"SELECT username, password FROM vpn;");

    // Execute the query
    if (mysql_query(connection, query) != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(connection));
    }

    result = mysql_store_result(connection);

    while((fetch_row = mysql_fetch_row(result)) != NULL){
        //check the logged username exist or not.
        if(strcmp(u_name,fetch_row[0]) == 0 && strcmp(u_password,fetch_row[1]) == 0)
            // printf("the user account exist\n");
            return LOGIN;
        else
            // printf("does not exist\n");
            return N_LOGIN;
    }

    // Close the connection and return success
    mysql_close(connection);
}

//Disable password echo : if we type the password it should be gather and can't echo to the user.
void Disable_pass_echo(){
    struct termios dis_pass_echo;
    tcgetattr(STDIN_FILENO,&dis_pass_echo);
    dis_pass_echo.c_lflag &= ~ECHO;
    //To make disable and enable echo password system.
}

void account_creator(){
    clearscn();
    char username[BUFF_M];
    printf(RED BOLD"create your name : "RESET);
    scanf("%s",username);

    char password[BUFF_M];
    printf(RED BOLD"create your password : "RESET);
    scanf("%s",password);

    if(strcmp(username,"") == 0 || strcmp(password,"") == 0)
        Error("The use credentials not found.");
    else
        //this create_new_account function init the all sql environment and it tells if any error aquired.
        create_new_account(username,password);
}

void create_new_account(char *u_name, char *u_password) {
    connection = mysql_init(NULL); // establish a database connection.

    // Initialization of SQL database server.
    if (connection == NULL)  
        fprintf(stderr,"%s",mysql_error(connection));

    // Get database connection parameters from file
    const char *db_server = "localhost";
    const char *db_user = "root";
    const char *db_password = "mohamed";
    const char *database_name = "vpn";

    // Connect to the database
    if (mysql_real_connect(connection, db_server, db_user, db_password, database_name, DB_PORT, NULL, 0) == NULL) {
        fprintf(stderr, "Connection failed: %s\n", mysql_error(connection));
        mysql_close(connection);
        exit(EXIT_FAILURE);
    } else {
        printf(GREEN BOLD"DB server status : SUCCESS\n");
    }

    // Prepare query string safely
    char query[256];
    snprintf(query, sizeof(query), "INSERT INTO vpn (username, password) VALUES ('%s', '%s')", u_name, u_password);

    // Execute the query
    if (mysql_query(connection, query) != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(connection));
    } else {
        printf(GREEN BOLD"Account create status : SUCCESS\n");
    }

    // Close the connection and return success
    mysql_close(connection);
}


/**
 *                                  DOCS FOR EXISTING USERS
 * If the user are existing user,he/her have session timeout obey on (sesssion layer of OSI).
 * if we have time for ending session generously login to this and enter.
*/

/**
 *                                  DATABASE MANAGEMENT SYSTEM
 * This for store,fetch,delete etc process from database
 * so,i have a function for this:
 *  1.To get data
 *  2.To connect to the database
 *  3.To delete the data
*/

//To get encrypted value from this.
void get_datas_enc(const char *data, int len) {
    for (int i = 0; i < len; i++) {
        // Cast to unsigned char to avoid sign extension issues
        printf("%02x", (unsigned char)data[i]);
    }
    printf("\n");
}

//print the help of this of this vpn
void print_help(char *arg){
    printf("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    printf("\t\t\t\t\tAVAILABLE ARGUMENTS\n");
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-\n\n");
    printf("-i [interface name] or --interface [interface name] :\t Capture tcp packets length for this interface.\n\n");
    printf("-v [vpn name] or --vpn [vpn name]\t\t    : \t Enter the vpn name to connect vpn server.\n\n");
    printf("     -s or --start \t\t\t\t    : \t This for vpn to start vpn server(with vpn server).\n\n");
    printf("-pt [packet name] or --packetname [packet name]\t    :\t which you want to capture.(eg.,tcp,icmp)\n\n");
    printf("-nu or --newUser\t\t\t\t    :\t Create new user account for this vpn.\n\n");
    printf("-eu or --existUser\t\t\t\t    :\t Log in from already exist account.\n\n");
    printf("-h or --help \t\t\t\t\t    :\t Help of this tool.\n\n");
    printf("Usage : %s <command>\n",arg);
}

// Error handling function
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * this function has to encrypt the given data and return it successfull or not.
*/
void get_aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        handleErrors();
    }

    // Provide the message to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, AES_BLOCK_SIZE)) {
        handleErrors();
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    printf("%s",output);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

//this function is used as tunnel to throw encrypted value and recive it in anonimity.
void aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        handleErrors();
    }

    // Provide the message to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, AES_BLOCK_SIZE)) {
        handleErrors();
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void cap_pack_tcp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    system("clear");
    u_char final_enc_val[AES_BLOCK_SIZE+AES_BLOCK_SIZE];
    //starts to capture packets
    printf(GREEN"\t\t\t\t\t\t Length of the packets captured : %d MB\\S\r\n\n",pkthdr->caplen);
    fflush(stdout);
    printf(GREEN"\t\t\t\t\t\t packet type\t\t\t: TCP\n");
    sleep(1);

    aes_encrypt(R_WORD,final_enc_val,SEC_KEY);

    // for(int i = 0;i < AES_BLOCK_SIZE;i++){
    //     printf("%02X ",final_enc_val[i]);
    // } 
    // printf("\n\n");
}

void cap_pack_icmp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    system("clear");
    u_char final_enc_val[AES_BLOCK_SIZE+AES_BLOCK_SIZE];
    //starts to capture packets
    printf(GREEN"\t\t\t\t\t\t Length of the packets captured : %d MB\\S\r\n\n",pkthdr->caplen);
    printf(GREEN"\t\t\t\t\t\t packet type\t\t\t: ICMP(ping)\n");
    fflush(stdout);
    sleep(1);

    aes_encrypt(R_WORD,final_enc_val,SEC_KEY);

    // for(int i = 0;i < AES_BLOCK_SIZE;i++){
    //     printf("%02X ",final_enc_val[i]);
    // } 
    // printf("\n\n");
}

/**
 * This function will to make packet reciver machine
 * it capture each tcp/ip and icmp packets.
*/
void init_pack(pcap_t *handle,char *interface_name,char *p_type){//p_type stands for packets type.
    char error[PCAP_ERRBUF_SIZE];
    struct bpf_program bp;
                                                
    handle = pcap_open_live(interface_name,BUFSIZ,1,1000,error);
    /*It capture network packets on 1 minute and it'll be continous loop.*/
    printf("[+]Capture on %s...\n",interface_name);

    if(handle == NULL){
        perror("pacp_open_live()");
        printf("Usage Interface : %s",interface_name);
        pcap_breakloop(handle);
    }

    if(pcap_compile(handle,&bp,p_type,0,0) == -1){
        perror("pcap_compile()");
        printf("Usage Interface : %s",interface_name);
        pcap_breakloop(handle);
        pcap_freecode(&bp);
    }

    if(pcap_setfilter(handle,&bp) == -1){
        printf("%s",pcap_geterr(handle));
        printf("Usage Interface : %s",interface_name);
        pcap_breakloop(handle);
        pcap_freecode(&bp);
    }

    if(strcmp(p_type,"tcp") == 0){
        if(pcap_loop(handle,0,cap_pack_tcp,NULL) < 0){
            perror("pcap_loop()");
            printf("Usage Interface %s",interface_name);
            pcap_breakloop(handle);
        }
    } else if(strcmp(p_type,"icmp") == 0){

        if(pcap_loop(handle,0,cap_pack_tcp,NULL) < 0){
            perror("pcap_loop()");
            printf("Usage Interface %s",interface_name);
            pcap_breakloop(handle);
        }
    } else {
        printf("Packet type not found : %s\n",p_type);
        exit(EXIT_FAILURE);
    }
    pcap_close(handle);
}

void vpn_server(char *s_name){
    struct sockaddr_in addr_sock,dst_addr;
    char dst_ip[INET_ADDRSTRLEN]; //its for store destination ip.
    SSL *ssl_init;
    SSL_CTX *ctx;
    int opt_l = 1;
    int sock_a;

    //initialize ssl
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    socklen_t dest_len = sizeof(dst_addr);

    //intialize ssl context.
    ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx){
        perror("init ssl context:");
        handleErrors();
        exit(EXIT_FAILURE);
    }

    //To init the certificate for connection and encrypted data.
    if(SSL_CTX_use_certificate_file(ctx,"server.crt",SSL_FILETYPE_PEM) == -1){
        perror("gen certificate");
        handleErrors();
        exit(EXIT_FAILURE);
    }

    //To generate private key
    if(SSL_CTX_use_PrivateKey_file(ctx,"server.key",SSL_FILETYPE_PEM) == -1){
        perror("gen private key");
        handleErrors();
        exit(EXIT_FAILURE);
    }

    //fill the socket address 
    addr_sock.sin_family = AF_INET;
    addr_sock.sin_addr.s_addr = INADDR_ANY;
    addr_sock.sin_port = htons(SOCK_PORT);

    int server = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if(server == -1){
        perror("init server");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&opt_l,sizeof(opt_l)) == -1){
        perror("setting server");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if(bind(server,(struct sockaddr *)&addr_sock,sizeof(addr_sock)) == -1){
        perror("Binding error:");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if(listen(server,3) == -1){
        perror("listen");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("Server %s%s%s successfully starts and is listen this port %d...\n\n",GREEN,s_name,RESET,SOCK_PORT);//it appear to the user,the server been starts
    printf(RED"\t\t\t%s\t\t\t\n",s_name); //appear server on red color

    sock_a = accept(server,(struct sockaddr *)&dst_addr,&dest_len);//for accept clients.

    if(sock_a < 0){
        perror("accept");
        close(server);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    inet_ntop(AF_INET,&dst_addr.sin_addr,dst_ip,INET_ADDRSTRLEN);

    int client_port = ntohs(dst_addr.sin_port);
    printf("\nThe client %s connect with port %d\n",dst_ip,client_port); 

    //Make new object for ssl
    ssl_init = SSL_new(ctx);

    if(!ssl_init){
        perror("init ssl");
        close(server);
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl_init,sock_a);

    if(SSL_accept(ssl_init) <= 0){
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_init);
        close(server);
        close(sock_a);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if(SSL_write(ssl_init,s_name,strlen(s_name)) == -1){
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_init);
        SSL_CTX_free(ctx);
        close(server);
        close(sock_a);
        exit(EXIT_FAILURE);
    }

    
    SSL_free(ssl_init);
    close(sock_a);
    close(server);
    SSL_CTX_free(ctx);
}

void Error(char *Err){
    printf(BOLD RED"error : %s%s%s.%s\n",RESET,WHITE BOLD,Err,RESET);
    return; //It suddenly exist,if it tells error.
}

void main_interface(){
    printf("\t\t\t\t\tInterface to vpn server\n\n\n");
    printf("\t\t\t%s1.Login\t\t\t\t\t\t2.Signup%s\n\n\n",BOLD,RESET);
}

int main(){
    /////////////initializer/////////////

    int choice;
    pcap_t *interface;
    char *user_choice;

    clearscn();
    main_interface();
    printf("Enter valid choice to continue : ");
    scanf("%d",&choice);

    if(choice > 2)  Error("your choice apart from valid choices");
    else if (choice == 1){ 
        clearscn();
        char username[BUFF_M];
        printf(RED BOLD"Enter your name : "RESET);
        scanf("%s",username);

        char password[BUFF_M];
        printf(RED BOLD"Enter your password : "RESET);
        scanf("%s",password);

        int is_logged = log_account(username,password);
    
        if(is_logged == LOGIN){
            //If user have a account in vpn server.it allow the user to use this server.
            printf("========================================================================================\n");
            printf("\t\t\t\t\tWelcome to our vpn server\n");
            printf("========================================================================================\n");
            printf("                                                                                          \n");
            printf("                                ██╗░░░██╗██████╗░███╗░░██╗\n");
            printf("                                ██║░░░██║██╔══██╗████╗░██║\n");
            printf("                                ╚██╗░██╔╝██████╔╝██╔██╗██║\n");
            printf("                                ░╚████╔╝░██╔═══╝░██║╚████║\n");
            printf("                                ░░╚██╔╝░░██║░░░░░██║░╚███║\n");
            printf("                                ░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚══╝\n");
            printf("========================================================================================\n\n");
            printf(GREEN BOLD"Now on the vpn interface...\n\n"RESET);
            sleep(5);
            clearscn();

            //Now get input from users to accomplish furthur tasks.
            while(1){
                printf(GREEN BOLD"%s > "RESET,username);
                scanf("%s",user_choice);

                if(strcmp(user_choice,"help") == 0){
                    printf("Jeichitom maara");break;
                }
            }
        } else {
            Error("The given user account not found in vpn server");
        }   
    } else if(choice == 2){
        clearscn();
        account_creator();
    }
}

/**
 * TODO : 
 * 1.To make ensure the login function.
 * 2.To make password has should been secure.
 * 3.make to capture the icmp packet:
 *      # we creates checksum for capture this packets.
*/