#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

void IP(struct in_addr src_ip, struct in_addr dst_ip)
{
	printf("S_IP : %d.%d.%d.%d\n", src_ip.s_addr & 0xff, (src_ip.s_addr >> 8) & 0xff, (src_ip.s_addr >> 16) & 0xff,  (src_ip.s_addr >> 24) & 0xff);
	printf("D_IP : %d.%d.%d.%d\n", dst_ip.s_addr & 0xff, (dst_ip.s_addr >> 8) & 0xff, (dst_ip.s_addr >> 16) & 0xff,  (dst_ip.s_addr >> 24) & 0xff);
}

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
                
                struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth_hdr));
               	printf("\n");
                IP(ip_hdr->ip_src, ip_hdr ->ip_dst);
                
                printf("\nBytes : ");
		printf("------------------");
                if(ntohs(eth_hdr->ether_type)!=ETHERTYPE_IP){
                        continue;
                }
        }

        pcap_close(pcap);
}
