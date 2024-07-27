#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

//define macros

#define BUFFER 1024
#define FALSE_IP "99.99.99.99"
#define TARGET_IP "8.8.8.8"
#define DEVICE "enx7a188b3fd951"

uint8_t chksum(const uint8_t *data){
    uint8_t checksum = 0,i;
    int sum = 0;

    if(strlen(data) < 1)
        return 0;

    for(i = 0;i < strlen(data);i++){
        sum += (unsigned char)data[i];
    }
    checksum = sum & 0xFF;
    return ~checksum;
}

int main(){
    int sock,*opt; //init socket
    struct sockaddr dest_ip;
    char packet_ip[BUFFER];
    char packet_icmp[BUFFER];
    struct iphdr *ip_header = (struct iphdr *)packet_ip;
    struct icmphdr *icmp_header = (struct icmphdr *)packet_icmp;

    //To fill ip header and icmp header

    ip_header->version = 4;
    ip_header->ttl = 64;
    ip_header->ihl = 5;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->tos = 0;
    ip_header->id = htons(1111);
    ip_header->daddr = inet_addr(FALSE_IP);
    ip_header->saddr = inet_addr(TARGET_IP);
    ip_header->check = chksum(packet_ip);

    sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    dest_ip.sa_family = AF_INET;

    if(sock == -1){
        perror("open socket");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)) == -1){
        perror("in socket setup");
        exit(EXIT_FAILURE);
    }

    if(sendto(sock,FALSE_IP,sizeof(FALSE_IP),0,(struct sockaddr *)&dest_ip,sizeof(dest_ip)) == -1){
        perror("in send");
    }
    
    //To create and make icmp echo and get packets
    
    pcap_t *handle;
    struct pcap_pkthdr *getstruct;
    char error[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(DEVICE,BUFSIZ,1,1000,error);

    //To define icmp echo header

    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->un.echo.id = htons(1);
    icmp_header->un.echo.sequence = htons(0);
    icmp_header->checksum = chksum(packet_icmp);

    if(handle == NULL){
        perror("in opening live");
        exit(EXIT_FAILURE);
    } else {
        printf("[+] Sniffing on %s...",DEVICE);
    }

    while(1){
        if(pcap_next(handle,getstruct) == NULL){
            perror("in pcap_next()");
            exit(EXIT_FAILURE);
        } else {
            printf("\n[+] Reply recieve\n");
        }
    }
}