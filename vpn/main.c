#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef unsigned char u_char;

//Define color macros
#define RESET       "\033[0m" //if any color aquired it reset and disapper after.
#define BOLD        "\033[1m"
#define UNDERLINE   "\033[4m"
#define REVERSED    "\033[7m"

#define BLACK       "\033[30m"
#define RED         "\033[31m" 
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define MAGENTA     "\033[35m"
#define CYAN        "\033[36m"
#define WHITE       "\033[37m"


//Define macros
#define SEC_KEY "helloworld" //thus, stands for secure key and thier value is "helloworld"

#define R_WORD "hw"

#define BUFF_M 100//it stands for macro buffer 

#define SOCK_PORT 8888

#define ENCPT_BUFF 32

#define LOGIN 10 //check login or not.if logged in it on.
/**
 * N_LOGIN : it checks the session will timout or not and the username and passwords
 * are valid
*/
#define N_LOGIN 20 //check this for no login this account
#define VALID 0 //check the packets are valid
#define N_VALID 1 //check the packets are invalid
#define SESSION_TIMEOUT 86400 //session will timout around on oneday

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

void new_user_acc(){
    u_char key[crypto_secretbox_KEYBYTES];
    u_char nonce[crypto_secretbox_NONCEBYTES];
    u_char enc_id[128];
    u_char decrypted[128];

    char name[BUFF_M];
    char password[8];

    printf("%s%sEnter Your Name :%s\n",BOLD,BLUE,RESET);//Get name from the user.
    scanf("%s\n",name);

    printf("%s%sEnter Password  :%s\n",BOLD,BLUE,RESET);
    scanf("%s\n",password);

    /**
     * the <sodium.h> have ability to another encryption function.
    */
    if(sodium_init() < 0){
        perror("sodium init");//initialize the sodium function
        exit(EXIT_FAILURE);
    }

    //generates randome things
    randombytes_buf(key,sizeof(key));
    randombytes_buf(nonce,sizeof(nonce));

    crypto_secretbox_easy(enc_id,strcat(name,password),sizeof(strcat(name,password)),nonce,key);
    //it encryptes the name and password and produce const output that is encrypted values.
}

/**
 *                                  DOCS FOR EXISTING USERS
 * If the user are existing user,he/her have session timeout obey on (sesssion layer of OSI).
 * if we have time for ending session generously login to this and enter.
*/

void get_datas_enc(const char *data,size_t len){
    for (size_t i = 0; i < strlen(len); i++) {
        printf("%02x", data[i]);
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
    int opt_l = 1;
    int sock_a;

    socklen_t dest_len = sizeof(dst_addr);
    socklen_t addr_len = sizeof(addr_sock);

    //fill the socket address 
    addr_sock.sin_family = AF_INET;
    addr_sock.sin_addr.s_addr = INADDR_ANY;
    addr_sock.sin_port = htons(SOCK_PORT);

    int server = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if(server == -1){
        perror("init server");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&opt_l,sizeof(opt_l)) == -1){
        perror("setting server");
        exit(EXIT_FAILURE);
    }

    if(bind(server,(struct sockaddr *)&addr_sock,sizeof(addr_sock)) == -1){
        perror("Binding error:");
        exit(EXIT_FAILURE);
    }

    if(listen(server,3) == -1){
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server %s%s%s successfully starts and is listen this port %d...\n\n",GREEN,s_name,RESET,SOCK_PORT);//it appear to the user,the server been starts
    printf(RED"\t\t\t%s\t\t\t\n",s_name); //appear server on red color

    if(sock_a = accept(server,(struct sockaddr *)&dst_addr,&dest_len) == -1){
        perror("accept");
        exit(EXIT_FAILURE);
    }

    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&dst_addr.sin_addr.s_addr,dst_ip,INET_ADDRSTRLEN);

    int client_port = ntohs(dst_addr.sin_port);
    printf("The client %s connect with port %d\n",dst_ip,client_port);

    close(server);
}

int main(int argc,char *argv[]){
    //We have 8 argumnets totally.
    pcap_t *interface;
    if(argc > 8 || argc < 0){
        print_help(argv[0]);
    } else if (strcmp("-h",argv[1]) == 0 || strcmp("--help",argv[1]) == 0){
        print_help(argv[0]);
    } else if (strcmp("-i",argv[1]) == 0 || strcmp("--interface",argv[1]) == 0){
        //check the user enter interface name or not.
        if(strcmp(argv[2],"") != 0){
            if(strcmp(argv[3],"-pt") == 0 || strcmp(argv[3],"--packetname") == 0){
                if(strcmp(argv[4],"tcp") == 0 || strcmp(argv[4],"icmp") == 0){
                    init_pack(interface,argv[2],argv[4]);
                } else {
                    print_help(argv[0]);
                }
            } else {
                print_help(argv[0]);
            }
        } else {
            print_help(argv[0]);
        }
    } else if(strcmp("-v",argv[1]) == 0 || strcmp("--vpn",argv[1]) == 0){
        /**
         * check the vpn enter name of the vpn server and starts.
        */
        if(strcmp(argv[2],"") == 0){
            print_help(argv[0]);
        } else if(strcmp(argv[3],"-s") == 0 || strcmp(argv[3],"--start") == 0){
            vpn_server(argv[2]);
        } else {
            print_help(argv[0]);
        }
    }
}