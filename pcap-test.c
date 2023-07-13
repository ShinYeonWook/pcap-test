#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,     
           ip_v:4;       
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       
           ip_hl:4;        
#endif
    u_int8_t ip_tos;       
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
    u_int16_t ip_len;        
    u_int16_t ip_id;          
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        
#endif
#ifndef IP_DF
#define IP_DF 0x4000     
#endif
#ifndef IP_MF
#define IP_MF 0x2000        
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   
#endif
    u_int8_t ip_ttl;          
    u_int8_t ip_p;            
    u_int16_t ip_sum;         
    struct in_addr ip_src, ip_dst;
};

void IP(struct in_addr src_ip, struct in_addr dst_ip)
{
	printf("S_IP : %d.%d.%d.%d\n", src_ip.s_addr & 0xff, (src_ip.s_addr >> 8) & 0xff, (src_ip.s_addr >> 16) & 0xff,  (src_ip.s_addr >> 24) & 0xff);
	printf("D_IP : %d.%d.%d.%d\n", dst_ip.s_addr & 0xff, (dst_ip.s_addr >> 8) & 0xff, (dst_ip.s_addr >> 16) & 0xff,  (dst_ip.s_addr >> 24) & 0xff);
}

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       
    u_int16_t th_dport;     
    u_int32_t th_seq;         
    u_int32_t th_ack;       
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,      
           th_off:4;       
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,       
           th_x2:4;     
#endif
    u_int8_t  th_flags;     
#ifndef TH_FIN
#define TH_FIN    0x01     
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      
#endif
#ifndef TH_RST
#define TH_RST    0x04     
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08  
#endif
#ifndef TH_ACK
#define TH_ACK    0x10     
#endif
#ifndef TH_URG
#define TH_URG    0x20    
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         
    u_int16_t th_sum;        
    u_int16_t th_urp;        
};

void port(u_int16_t src_port, u_int16_t dst_port)
{
	printf("S_port: %d\n", ntohs(src_port));
	printf("D_port: %d\n", ntohs(dst_port));
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

void printdata(int d_len, u_char* data)
{
	if(d_len == 0)
	{
	printf("0 Bytes\n");
	return;
	}
	printf("%d bytes\n", d_len);
	printf("Data: ");
	if(d_len < 10)
	{
		for(int i=0;i<=d_len;i++)
		{
		printf("%02X ",data[i]);
		}
	}
	else
	{
		for(int j=0;j<=9;j++)
		{
		printf("%02X ",data[j]);
		}	
	}
	printf("- - - - \n");
	
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
                
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(*eth_hdr) + ip_hdr->ip_hl*4); 
                port(tcp_hdr -> th_sport, tcp_hdr -> th_dport);
                
                u_char *data = (u_char *)(packet + sizeof(*eth_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
                int d_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl*4 + tcp_hdr->th_off*4);
                printdata(d_len,data);
                
                printf("\nBytes : ");
		printf("------------------");
                if(ntohs(eth_hdr->ether_type)!=ETHERTYPE_IP){
                        continue;
                }
        }

        pcap_close(pcap);
}
