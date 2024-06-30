#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <net/ethernet.h>

char *get_mac(const struct ether_header *getinfo) {
    static char MAC_addr[20];
    sprintf(MAC_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            getinfo->ether_dhost[0], getinfo->ether_dhost[1],
            getinfo->ether_dhost[2], getinfo->ether_dhost[3],
            getinfo->ether_dhost[4], getinfo->ether_dhost[5]);
    return MAC_addr;
}

int main() {
    struct ether_header header;
    // For demonstration purposes, we'll manually set the MAC address here
    unsigned char mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    memcpy(header.ether_dhost, mac, sizeof(mac));

    char *mac_addr = get_mac(&header);
    printf("Mac Addr : %s\n", mac_addr);

    return 0;
}
