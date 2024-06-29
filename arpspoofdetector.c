#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>

//define some funtions
void print_help();

void print_start(){
    printf("\n");
    printf("               AAA               RRRRRRRRRRRRRRRRR   PPPPPPPPPPPPPPPPP           SSSSSSSSSSSSSSS PPPPPPPPPPPPPPPPP        OOOOOOOOO          OOOOOOOOO     FFFFFFFFFFFFFFFFFFFFFF \n"); 
    printf("              A:::A              R::::::::::::::::R  P::::::::::::::::P        SS:::::::::::::::SP::::::::::::::::P     OO:::::::::OO      OO:::::::::OO   F::::::::::::::::::::F \n");
    printf("             A:::::A             R::::::RRRRRR:::::R P::::::PPPPPP:::::P      S:::::SSSSSS::::::SP::::::PPPPPP:::::P  OO:::::::::::::OO  OO:::::::::::::OO F::::::::::::::::::::F \n");
    printf("            A:::::::A            RR:::::R     R:::::RPP:::::P     P:::::P     S:::::S     SSSSSSSPP:::::P     P:::::PO:::::::OOO:::::::OO:::::::OOO:::::::OFF::::::FFFFFFFFF::::F \n");
    printf("           A:::::::::A             R::::R     R:::::R  P::::P     P:::::P     S:::::S              P::::P     P:::::PO::::::O   O::::::OO::::::O   O::::::O  F:::::F       FFFFFF \n");
    printf("          A:::::A:::::A            R::::R     R:::::R  P::::P     P:::::P     S:::::S              P::::P     P:::::PO:::::O     O:::::OO:::::O     O:::::O  F:::::F              \n");
    printf("         A:::::A A:::::A           R::::RRRRRR:::::R   P::::PPPPPP:::::P       S::::SSSS           P::::PPPPPP:::::P O:::::O     O:::::OO:::::O     O:::::O  F::::::FFFFFFFFFF    \n");
    printf("        A:::::A   A:::::A          R:::::::::::::RR    P:::::::::::::PP         SS::::::SSSSS      P:::::::::::::PP  O:::::O     O:::::OO:::::O     O:::::O  F:::::::::::::::F    \n");
    printf("       A:::::A     A:::::A         R::::RRRRRR:::::R   P::::PPPPPPPPP             SSS::::::::SS    P::::PPPPPPPPP    O:::::O     O:::::OO:::::O     O:::::O  F:::::::::::::::F    \n");
    printf("      A:::::AAAAAAAAA:::::A        R::::R     R:::::R  P::::P                        SSSSSS::::S   P::::P            O:::::O     O:::::OO:::::O     O:::::O  F::::::FFFFFFFFFF    \n");
    printf("     A:::::::::::::::::::::A       R::::R     R:::::R  P::::P                             S:::::S  P::::P            O:::::O     O:::::OO:::::O     O:::::O  F:::::F              \n");
    printf("    A:::::AAAAAAAAAAAAA:::::A      R::::R     R:::::R  P::::P                             S:::::S  P::::P            O::::::O   O::::::OO::::::O   O::::::O  F:::::F              \n");
    printf("   A:::::A             A:::::A   RR:::::R     R:::::RPP::::::PP               SSSSSSS     S:::::SPP::::::PP          O:::::::OOO:::::::OO:::::::OOO:::::::OFF:::::::FF            \n");
    printf("  A:::::A               A:::::A  R::::::R     R:::::RP::::::::P               S::::::SSSSSS:::::SP::::::::P           OO:::::::::::::OO  OO:::::::::::::OO F::::::::FF            \n");
    printf(" A:::::A                 A:::::A R::::::R     R:::::RP::::::::P               S:::::::::::::::SS P::::::::P             OO:::::::::OO      OO:::::::::OO   F::::::::FF            \n");
    printf("AAAAAAA                   AAAAAAARRRRRRRR     RRRRRRRPPPPPPPPPP                SSSSSSSSSSSSSSS   PPPPPPPPPP               OOOOOOOOO          OOOOOOOOO     FFFFFFFFFFF            \n\n");

    printf(" DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEETTTTTTTTTTTTTTTTTTTTTTTEEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCCTTTTTTTTTTTTTTTTTTTTTTT     OOOOOOOOO     RRRRRRRRRRRRRRRRR      \n");      
    printf(" D::::::::::::DDD   E::::::::::::::::::::ET:::::::::::::::::::::TE::::::::::::::::::::E    CCC::::::::::::CT:::::::::::::::::::::T   OO:::::::::OO   R::::::::::::::::R     \n");      
    printf(" D:::::::::::::::DD E::::::::::::::::::::ET:::::::::::::::::::::TE::::::::::::::::::::E  CC:::::::::::::::CT:::::::::::::::::::::T OO:::::::::::::OO R::::::RRRRRR:::::R    \n");      
    printf(" DDD:::::DDDDD:::::DEE::::::EEEEEEEEE::::ET:::::TT:::::::TT:::::TEE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::CT:::::TT:::::::TT:::::TO:::::::OOO:::::::ORR:::::R     R:::::R   \n");      
    printf("   D:::::D    D:::::D E:::::E       EEEEEETTTTTT  T:::::T  TTTTTT  E:::::E       EEEEEEC:::::C       CCCCCCTTTTTT  T:::::T  TTTTTTO::::::O   O::::::O  R::::R     R:::::R   \n");      
    printf("   D:::::D     D:::::DE:::::E                     T:::::T          E:::::E            C:::::C                      T:::::T        O:::::O     O:::::O  R::::R     R:::::R   \n");      
    printf("   D:::::D     D:::::DE::::::EEEEEEEEEE           T:::::T          E::::::EEEEEEEEEE  C:::::C                      T:::::T        O:::::O     O:::::O  R::::RRRRRR:::::R    \n");      
    printf("   D:::::D     D:::::DE:::::::::::::::E           T:::::T          E:::::::::::::::E  C:::::C                      T:::::T        O:::::O     O:::::O  R:::::::::::::RR     \n");      
    printf("   D:::::D     D:::::DE:::::::::::::::E           T:::::T          E:::::::::::::::E  C:::::C                      T:::::T        O:::::O     O:::::O  R::::RRRRRR:::::R    \n");      
    printf("   D:::::D     D:::::DE::::::EEEEEEEEEE           T:::::T          E::::::EEEEEEEEEE  C:::::C                      T:::::T        O:::::O     O:::::O  R::::R     R:::::R   \n");      
    printf("   D:::::D     D:::::DE:::::E                     T:::::T          E:::::E            C:::::C                      T:::::T        O:::::O     O:::::O  R::::R     R:::::R   \n");      
    printf("   D:::::D    D:::::D E:::::E       EEEEEE        T:::::T          E:::::E       EEEEEEC:::::C       CCCCCC        T:::::T        O::::::O   O::::::O  R::::R     R:::::R   \n");      
    printf(" DDD:::::DDDDD:::::DEE::::::EEEEEEEE:::::E      TT:::::::TT      EE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::C      TT:::::::TT      O:::::::OOO:::::::ORR:::::R     R:::::R   \n");      
    printf(" D:::::::::::::::DD E::::::::::::::::::::E      T:::::::::T      E::::::::::::::::::::E  CC:::::::::::::::C      T:::::::::T       OO:::::::::::::OO R::::::R     R:::::R   \n");      
    printf(" D::::::::::::DDD   E::::::::::::::::::::E      T:::::::::T      E::::::::::::::::::::E    CCC::::::::::::C      T:::::::::T         OO:::::::::OO   R::::::R     R:::::R   \n");      
    printf(" DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEE      TTTTTTTTTTT      EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC      TTTTTTTTTTT           OOOOOOOOO     RRRRRRRR     RRRRRRR   \n\n"); 

    printf(" VVVVVVVV           VVVVVVVV  1111111                000000000         \n");                                                                                                           
    printf(" V::::::V           V::::::V 1::::::1              00:::::::::00       \n");                                                                                                           
    printf(" V::::::V           V::::::V1:::::::1            00:::::::::::::00     \n");                                                                                                           
    printf(" V::::::V           V::::::V111:::::1           0:::::::000:::::::0    \n");                                                                                                           
    printf("  V:::::V           V:::::V    1::::1           0::::::0   0::::::0    \n");                                                                                                           
    printf("   V:::::V         V:::::V     1::::1           0:::::0     0:::::0    \n");                                                                                                           
    printf("    V:::::V       V:::::V      1::::1           0:::::0     0:::::0    \n");                                                                                                           
    printf("     V:::::V     V:::::V       1::::l           0:::::0 000 0:::::0    \n");                                                                                                           
    printf("      V:::::V   V:::::V        1::::l           0:::::0 000 0:::::0    \n");                                                                                                           
    printf("       V:::::V V:::::V         1::::l           0:::::0     0:::::0    \n");                                                                                                           
    printf("        V:::::V:::::V          1::::l           0:::::0     0:::::0    \n");                                                                                                           
    printf("         V:::::::::V           1::::l           0::::::0   0::::::0    \n");                                                                                                           
    printf("          V:::::::V         111::::::111        0:::::::000:::::::0    \n");                                                                                                           
    printf("           V:::::V          1::::::::::1 ......  00:::::::::::::00     \n");                                                                                                           
    printf("            V:::V           1::::::::::1 .::::.    00:::::::::00       \n");                                   
    printf("             VVV            111111111111 ......      000000000         \n\n");      
}

void packet_info(unsigned char *args,const struct pcap_pkthdr *handler,const unsigned char *packet){
    char *time_info = ctime(&handler->ts.tv_sec); 
    struct ether_header *getinfo;
    printf("\n---------------------------------------------\n");
    printf("Packet recieved at : %s",time_info);
    printf("Length of captured packet : %d\n",handler->caplen);
    printf("Total number packets captured : %d\n",handler->len);
    printf("Packet type : %d\n",getinfo->ether_type);
    printf("Send packets from : %s:%s:%s:%s:%s:%s\n",ntohs(getinfo->ether_dhost));
    printf("\n---------------------------------------------\n");
    printf("\n");
}

int capture_network_packets(char *interface_name){
    int is_state;
    struct bpf_program total_struct;
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface_name,BUFSIZ,1,1000,error);

    if(strcmp(interface_name,"") == 0){
        printf("Error found : interface name not found !\n");
        is_state = 0;
        exit(1);
    } else {
        is_state = 1;
    }

    if(handle == NULL){
        printf("Cannot action live, Due to %s\n",error);
        is_state = 0;
        exit(1);
    } else {
        is_state = 1;
    }  

    if(pcap_compile(handle,&total_struct,"ip",1,PCAP_NETMASK_UNKNOWN) == -1){
        printf("BPF Compilation error\n");
        is_state = 0;
        exit(1);
    } else {
        is_state = 1;
    }
    if(pcap_setfilter(handle,&total_struct) == -1){
        printf("Pcap filtering error\n");
        is_state = 0;
        exit(1);
    } else {
        is_state = 1;

    } if(is_state == 1){
        printf("Listening on %s\n",interface_name);
        pcap_loop(handle,-1,packet_info,error);
    } else {
        printf("Error Aquired!\n");
        print_help();
    }
}

void print_help(){
    printf("------------------------------------------------------\n");
    printf("The available arguments\n");
    printf("------------------------------------------------------\n");
    printf("-h or --help \t\t\t\t\t: Print the help of the tool\n\n");
    printf("-l or --lookup \t\t\t\t\t: Show all network interface name from the device\n\n");
    printf("-i [interface name] or --interface [interface name] : Start to capture the network packets from the given interface\n\n");
    printf("-v or --version \t\t\t\t: Show the verison of the tool\n");
    exit(1);
}

void print_available_interface(){
    pcap_if_t *device_name,*all_device;
    char error[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&all_device,error) == -1){
        printf("Cannot find devices due to : %s\n",error);
    }
        for(device_name = all_device;device_name;device_name = device_name -> next){
            printf("Device name : %s\n",device_name->name);
        }
}

int main(int argc,char *argv[]){
    if(argc > 3){
        printf("Given arguments are too high!\n");
        print_help();
    } else if(strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"--help") == 0){
        print_start();
        print_help();
    } else if(strcmp(argv[1],"-l") == 0 || strcmp(argv[1],"--lookup") == 0){
        print_start();
        printf("--------------------------------------\n");
        printf("THE AVAILABLE INTERFACES:\n");
        printf("--------------------------------------\n");
        print_available_interface();
        printf("--------------------------------------\n");
    } else if(strcmp(argv[1],"-v") == 0 || strcmp(argv[1],"--version") == 0){
        printf("ARP SPOOF DETECTOR V0.1\n");
    } else if(strcmp(argv[1],"-i") == 0 || strcmp(argv[1],"--interface") == 0){
        capture_network_packets(argv[2]);
    } else {
        printf("Invalid arguments.\n");
        print_help();
        printf("Usage : %s",argv[0]);
    }
}