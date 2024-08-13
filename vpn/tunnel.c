#include <stdio.h>
#include <openssl/sha.h>
#include <pcap.h>
#include <string.h>

void xor_encrypt_int(unsigned int *value, unsigned int key) {
    *value ^= key;
}

void xor_encrypt_char(unsigned char *data, size_t data_len, const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}


int tunnel(struct pcap_pkthdr *infos){
    char key[] = "!@)(_#@)";
    int pack_len = infos->caplen;
    int this_pack_len = infos->len;

    xor_encrypt_int(pack_len,key);
    xor_encrypt_int(pack_len,key);
    return 0;
}
