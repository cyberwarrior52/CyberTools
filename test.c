#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main() {
    pcap_if_t *all_devices, *device;
    pcap_addr_t *device_address;
    char error[PCAP_ERRBUF_SIZE];

    // Find all available network devices
    if (pcap_findalldevs(&all_devices, error) == -1) {
        printf("Cannot find devices due to: %s\n", error);
        return 1;
    }

    // Iterate over each network device found
    for (device = all_devices; device; device = device->next) {
        printf("Device name: %s\n", device->name);

        // Iterate over each address of the device
        for (device_address = device->addresses; device_address; device_address = device_address->next) {
            if (device_address->addr->sa_family == AF_INET) {
                // IPv4 address
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)device_address->addr;
                printf("  Device IPv4 Address: %s\n", inet_ntoa(ipv4->sin_addr));

                // Print broadcast address if available
                if (device_address->broadaddr) {
                    struct sockaddr_in *bcast = (struct sockaddr_in *)device_address->broadaddr;
                    printf("  Broadcast IPv4 Address: %s\n", inet_ntoa(bcast->sin_addr));
                } else {
                    printf("  Broadcast IPv4 Address: Not available\n");
                }
            }
            else if (device_address->addr->sa_family == AF_INET6) {
                // IPv6 address
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)device_address->addr;
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ipv6->sin6_addr, ip6, sizeof(ip6));
                printf("  Device IPv6 Address: %s\n", ip6);

                // Print IPv6 broadcast address if available
                if (device_address->broadaddr) {
                    struct sockaddr_in6 *bcast6 = (struct sockaddr_in6 *)device_address->broadaddr;
                    char ip6_bcast[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &bcast6->sin6_addr, ip6_bcast, sizeof(ip6_bcast));
                    printf("  IPv6 Broadcast Address: %s\n", ip6_bcast);
                } else {
                    printf("  IPv6 Broadcast Address: Not available\n");
                }
            }
        }
        printf("\n");
    }

    // Free the list of devices
    pcap_freealldevs(all_devices);

    return 0;
}
