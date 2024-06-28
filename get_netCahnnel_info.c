#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main(){
    pcap_if_t *device_name,*all_device;
    pcap_addr_t *device_address;
    char error[PCAP_ERRBUF_SIZE];
    
    if(pcap_findalldevs(&all_device,error) == -1){
        printf("Cannot find devices due to : %s\n",error);
    }
        for(device_name = all_device;device_name;device_name = device_name -> next){
        printf("Device name : %s\n",device_name->name);

        for(device_address = device_name->addresses; device_address; device_address = device_address->next){
            
            if(device_address->addr->sa_family == AF_INET){
                struct sockaddr_in *ipAddress = (struct sockaddr_in *)device_address->addr;
                struct sockaddr_in *netmask_Address = (struct sockaddr_in *)device_address->netmask;
                printf("Device ip : %s\n",inet_ntoa(ipAddress->sin_addr));
                printf("Netmask address : %s\n",inet_ntoa(netmask_Address->sin_addr));
                break;
            }

            for(device_address = device_name->addresses; device_address; device_address = device_address->next){
                if(device_address->addr -> sa_family == AF_INET6){
                    struct sockaddr_in6 *Bcastaddress = (struct sockaddr_in6 *)device_address->broadaddr;
                    char bcastaddr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6,&Bcastaddress->sin6_addr,bcastaddr,sizeof(bcastaddr));
                    printf("Broadcast address : %s\n",bcastaddr);
                } else {
                    printf("Broadcast address not found !\n");
                    break;
                }
            }
        }
        printf("\n");
    }
}
