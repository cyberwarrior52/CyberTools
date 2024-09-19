#include <pcap.h>
typedef unsigned char u_char;

#define DB_PORT 3306 //To establish database port 

#define SQL_INIT_FAILED -1
#define SQL_CONNECTION_FAILED -2
#define SQL_QUERY_FAILED -3

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

//To get length of encryption
#define MAX_NAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_ENCRYPTED_LENGTH (crypto_secretbox_MACBYTES + MAX_NAME_LENGTH + MAX_PASSWORD_LENGTH)

//Define macros
#define WELCOME_MESSAGE "Welcome our vpn server"

#define DB_FILE_NAME "db.txt"

#define SEC_KEY "helloworld" //thus, stands for secure key and thier value is "helloworld"

#define R_WORD "hw"

#define BUFF_M 100//it stands for macro buffer 

#define SOCK_PORT 6666

#define ENCPT_BUFF 32

#define LOGIN 10 //check login or not.if logged in it on.
#define N_LOGIN 20 //check this for no login this account
/**
 * N_LOGIN : it checks the session will timout or not and the username and passwords
 * are valid
*/
#define VALID 0 //check the packets are valid
#define N_VALID 1 //check the packets are invalid

//function prototypes for main function
void vpn_server(char *s_name);
void init_pack(pcap_t *handle,char *interface_name,char *p_type);
int log_account(char *u_name, char *u_password);
void create_new_account(char *u_name, char *u_password);
void clearscn();
void get_datas_enc(const char *data, int len);
void print_help(char *arg);
void handleErrors(void);
void get_aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key);
void aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key);
void cap_pack_tcp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void cap_pack_icmp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void Error(char *Err);
void account_creator();
void main_interface();
void Disable_pass_echo();
void Enable_pass_echo();