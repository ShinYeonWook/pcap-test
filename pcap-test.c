#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ethernet_hdr
{
        u_int8_t ether_dhost[ETHER_ADDR_LEN];
        u_int8_t ether_shost[ETHER_ADDR_LEN];
        u_int16_t ether_type;
};

void printMac(u_int8_t *m)
{
        printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
}

void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
}

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

int main(int argc, char* argv[]) {
        if (!parse(&param, argc, argv))
                return -1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }
                printf("%u bytes captured\n", header->caplen);
                struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		printf("MAC_S : ");
                printMac(eth_hdr->ether_shost);
                printf("\nMAC_D : ");
                printMac(eth_hdr->ether_dhost);
                printf("\nBytes : ");
		printf("------------------");
                if(ntohs(eth_hdr->ether_type)!=ETHERTYPE_IP){
                        continue;
                }
        }

        pcap_close(pcap);
}
