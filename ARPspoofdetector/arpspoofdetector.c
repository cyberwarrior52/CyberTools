#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define ARP_REQUESTS 1
#define ARP_RESPONSE 2

typedef struct _arp_hdr arp_hdr;
struct arp_hdr {
    uint16_t htype;    // Hardware type
    uint16_t ptype;    // Protocol type
    uint8_t hlen;      // Hardware address length
    uint8_t plen;      // Protocol address length
    uint16_t oper;     // Operation code (request or reply)
    uint8_t sha[6];    // Sender hardware address
    uint8_t spa[4];    // Sender IP address
    uint8_t tha[6];    // Target hardware address
    uint8_t tpa[4];    // Target IP address
};

void print_help();

void print_start(){
    //Define ascii for tool name
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
void alert_spoof(char *ip, char *mac){
	printf("\nAlert: Possible ARP Spoofing Detected. IP: %s and MAC: %s\n", ip, mac);
} 

//get mac address from the reciever
char *get_reciever_mac(const struct ether_header *getinfo) {
    static char MAC_addr[20]; //reciever mac buffer
    sprintf(MAC_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            getinfo->ether_dhost[0], getinfo->ether_dhost[1],
            getinfo->ether_dhost[2], getinfo->ether_dhost[3],
            getinfo->ether_dhost[4], getinfo->ether_dhost[5]);
    return MAC_addr; // create and return that address
}

char *get_sender_ip(uint8_t ip[4]){
    char *IP_addr = (char *)malloc(20*sizeof(char));
    sprintf(IP_addr,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
    return IP_addr;
}

char *get_reciever_ip(uint8_t ip[4]){
    char *IP_addr = (char *)malloc(20*sizeof(char));
    sprintf(IP_addr,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
    return IP_addr;
}

//get mac address from sender 
char *get_sender_mac(const struct ether_header *getinfo) {
    static char MAC_addr[20]; //sender mac buffer
    sprintf(MAC_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            getinfo->ether_shost[0], getinfo->ether_shost[1],
            getinfo->ether_shost[2], getinfo->ether_shost[3],
            getinfo->ether_shost[4], getinfo->ether_shost[5]);
    return MAC_addr;
}

void capture_network_packets(char *interface_name){
    pcap_t *handle;
    time_t start_timer,end_timer;
    long int diff;
    char error[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    struct pcap_pkthdr handler;
    int counter = 0;

    handle = pcap_open_live(interface_name,BUFSIZ,1,1000,error);

    //if interface name is empty it show error message like this
    if(strcmp(interface_name,"") == 0){
        printf("Error found : interface name not found !\n");
        exit(1);
    }
    if(handle == NULL){
        printf("Cannot action live, Due to %s\n",error);
        exit(1);
    } else {
        printf("\nListening on %s....\n",interface_name);
        system("clear");
    }
    start_timer = time(NULL);
    while(1){
        packet = pcap_next(handle,&handler);
        
        if(packet == NULL){
            printf("Error Aquired : %s\n",pcap_geterr(handle));
        }
        struct ether_header *getinfo = (struct ether_header *)packet;
        uint16_t ether_type = ntohs(getinfo->ether_type);

        if(ether_type == ETHERTYPE_ARP){
            start_timer = time(NULL);
            diff = start_timer - end_timer;
            if(diff > 20){
                counter = 0;
            }


            time_t cap_time = handler.ts.tv_sec;
            char *s_mac_addr = get_sender_mac(getinfo);
            char *r_mac_addr = get_reciever_mac(getinfo);
            char *time_info = ctime(&cap_time);
            struct arp_hdr *get_arp_details = (struct arp_hdr *)(packet+14);
            char *s_ip_addr = get_sender_ip(get_arp_details->spa);
            char *r_ip_addr = get_reciever_ip(get_arp_details->tpa);

            printf("\n---------------------------------------------\n");
            printf("Packet recieved at : %s",time_info);
            printf("Length of captured packet : %d\n",handler.caplen);
            printf("Total number packets captured : %d\n",ETHER_ADDR_LEN);
            printf("Operation type : %s\n",((ntohs(get_arp_details->oper) == ARP_REQUESTS) ? "ARP Request" : "ARP Response"));
            printf("Packet type : %d(ARP)\n",ether_type);
            printf("Sender MAC: %s\n",s_mac_addr);
            printf("Reciever MAC: %s\n",r_mac_addr);
            printf("Sender ip : %s\n",s_ip_addr);
            printf("Reciever ip : %s",r_ip_addr);
            printf("\n---------------------------------------------\n");
            printf("\n");
            
            counter++;
            end_timer = time(NULL);
            if(counter > 10){
                alert_spoof(s_ip_addr, s_mac_addr);
            }

        }
        
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

//show all interface from your device and list it all.
void print_available_interface(){
    pcap_if_t *device_name,*all_device;
    char error[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&all_device,error) == -1){
        printf("Cannot find devices due to : %s\n",error);
    }
        printf("--------------------------------------\n");
        printf("THE AVAILABLE INTERFACES:\n");
        printf("--------------------------------------\n");
        for(device_name = all_device;device_name;device_name = device_name -> next){
            printf("Device name : %s\n",device_name->name);
        }
        printf("--------------------------------------\n");
}

int main(int argc,char *argv[]){
    if(argc > 3){
        printf("Given arguments are too high!\n");
        print_help();
    } else if(argc == 1){
        print_start();
        print_help();
    } else if(strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"--help") == 0){
        print_start();
        print_help();
    } else if(strcmp(argv[1],"-l") == 0 || strcmp(argv[1],"--lookup") == 0){
        print_start();
        print_available_interface();
    } else if(strcmp(argv[1],"-v") == 0 || strcmp(argv[1],"--version") == 0){
        //Shows the version of the tool
        printf("ARP SPOOF DETECTOR V0.1\n");
    } else if(strcmp(argv[1],"-i") == 0 || strcmp(argv[1],"--interface") == 0){
        if(argc < 3){
            system("clear");
            print_start();
            print_available_interface();
            printf("Usage : %s [Your command should has been interface name : -l / --lookup]\n",argv[0]);
        } else {
            capture_network_packets(argv[2]);
        }
    } else {
        printf("Invalid arguments.\n");
        print_help();
        printf("Usage : %s",argv[0]);
    }
}