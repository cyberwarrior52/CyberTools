#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

// Checksum function
uint16_t chksum(void *data, int length) {
    uint32_t sum = 0;
    uint16_t *pkt = data;

    while (length > 1) {
        sum += *pkt++;
        length -= 2;
    }

    if (length == 1)
        sum += *(uint8_t *)pkt;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

/**we should set the limitation of ip Address
 * Limit of ip address is depends on class of Ip
 * limitation(255.255.255.255)
*/
static char *IpGenerator(char IP[16],int *block1,int *block2,int *block3,int *block4){
    // char IP[16];
    snprintf(IP,16,"%d.%d.%d.%d",*block1,*block2,*block3,*block4);
    (*block4)++;
    if(*block4 > 255){
        (*block4) = 0;
        if(*block3 > 255){
            (*block3) = 0;
            if(*block2 > 255){
                (*block2) = 0;
                if(*block1 > 255){
                    (*block1) = 144;
                }
            }
        }
    }
    return IP;
}

// Function to create ICMP echo request packets
void make_packets(char *src,char *dest, char *pack) {
    struct icmphdr *icmp_pack = (struct icmphdr *)(pack + sizeof(struct iphdr));
    struct iphdr *ip_header = (struct iphdr *)pack;

    // Fill in the ICMP Header
    icmp_pack->type = ICMP_ECHO;
    icmp_pack->code = 0;
    icmp_pack->un.echo.id = htons(1223);
    icmp_pack->un.echo.sequence = htons(1);
    icmp_pack->checksum = 0;
    icmp_pack->checksum = chksum((uint16_t *)icmp_pack, sizeof(struct icmphdr));

    // Fill in the IP Header
    ip_header->saddr = inet_addr(src);
    ip_header->daddr = inet_addr(dest);
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_header->id = htons(54321); // Packet ID
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->check = 0;
    ip_header->check = chksum((uint16_t *)ip_header, sizeof(struct iphdr));

    printf("ICMP packet created successfully.\n");
}

// Function to send the packet
void send_packet(char *dst_ip, char *data_buff, size_t data_size) {
    struct sockaddr_in sock;
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = inet_addr(dst_ip);

    int socket_init = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int sock_opt_val = 1;

    if (socket_init < 0) {
        perror("init socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(socket_init, IPPROTO_IP, IP_HDRINCL, &sock_opt_val, sizeof(sock_opt_val)) < 0) {
        perror("[-] Error! Cannot set IP_HDRINCL");
        exit(EXIT_FAILURE);
    }

    if (sendto(socket_init, data_buff, data_size, 0, (struct sockaddr *)&sock, sizeof(sock)) == -1) {
        perror("in send pack");
        exit(EXIT_FAILURE);
    }

    printf("Spoofed ICMP packet sent successfully.\n");
}

int main() {
    char buffer[126];
    int a=136,b=0;
    int c=0,d=0;
    int packet_count = 10,count=1;
    char src_ip[16]; //our custome destination ip

    while(count <= packet_count){
        IpGenerator(src_ip,&a,&b,&c,&d);
        make_packets(src_ip,"0.0.0.0", buffer);
        send_packet(src_ip, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr));
        snprintf(src_ip,sizeof(src_ip),"%d.%d.%d.%d",a,b,c,d);
        sleep(1);
        count++;
    }
    return 0;
}