#include <stdio.h>
#include <pcap.h>

void packet_handler(unsigned char *args,const struct pcap_pkthdr *handler,const unsigned char *packet){
    printf("Time of captured the packet : %ld\n",handler->ts.tv_sec);
    printf("Length of captured packet : %d\n",handler->caplen);
    printf("Total number packets captured : %d\n",handler->len);
    printf("\n");
}

int main(){
    char *Channel = "enx4eb0140926c1";
    struct bpf_program total_struct;
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(Channel,BUFSIZ,1,1000,error);

    if(handle == NULL){
        printf("Cannot action live, Due to %s\n",error);
    } else {
        printf("Live opened...\n");
    }

    if(pcap_compile(handle,&total_struct,"ip",1,PCAP_NETMASK_UNKNOWN) == -1){
        printf("BPF Compilation error\n");
    } else {
        printf("BPF Compilation success...\n");
    }

    if(pcap_setfilter(handle,&total_struct) == -1){
        printf("Pcap filtering error\n");
    } else {
        printf("Pcap successfully filtered...\n");
    }

    pcap_loop(handle,-1,packet_handler,error);

}