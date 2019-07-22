/*
 * Author = Nam Hyun Hee
 * Description = Pcap Capture Program
 */


#include <pcap.h>
#include <cstdio>       // #include <stdio.h> => <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>

#define EHT_TYPE_IPv4 0x0800
#define ETH_LENGTH 6
#define IP_LENGTH 4
#define IP_PROTOCOL 0x06
#define ETH_HEADER_LENGTH 14
#define TCP_FLAG_PHS_ACK 0x018
#define PRINT_COUNT 10

struct eth_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct ip_header{
    uint8_t ver_ihl;   // 8bit = IPv4 + header length -> header length*4 = Byte
    uint8_t type;
    uint8_t len[2];
    uint16_t id;
    uint16_t ip_flag;
    uint8_t time_to_live;
    uint8_t ip_protocol;
    uint16_t ip_checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct tcp_header{
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t Hlen;
    uint8_t tcp_flag;   // HTTP Data == tcp_flag 0x018 => PSH, ACK
    uint8_t win_size[2];
    uint16_t tcp_checksum;
    uint8_t urg_point[2];
};

void usage() {
    printf("[-] syntax: pcap_test <interface>\n");
    printf("[-] sample: pcap_test wlan0\n");
}

void printf_ethernet(uint8_t* mac){

    for(int i = 0; i<ETH_LENGTH; i++){
        if (i==(ETH_LENGTH-1)){
            printf("%02x\n", mac[i]);
        }
        else{
            printf("%02x : ", mac[i]);
        }
    }
}


void printf_ip(uint8_t* ip){
    for(int i = 0; i<IP_LENGTH; i++){
        if (i==(IP_LENGTH-1)){
            printf("%u\n", ip[i]);
        }
        else{
            printf("%u.", ip[i]);
        }
    }
}

void printf_port(uint8_t* port){
    printf("%d\n", (port[0]<<8) | port[1]);
}

void printf_Data(){
    printf("[+] HTTP Data");
}


int main(int argc, char* argv[]) {
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);    // open_live - linux , file : open_offline

    if (argc != 2) {
        usage();
        return -1;
  }

    if (handle == NULL) {
        fprintf(stderr, "[-] couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;     //pkthdr => timestamp, length
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // &packet : buffer pointer
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        const struct eth_header* eth  = (struct eth_header*)packet; // print mac
        const struct ip_header*  ip   = (struct ip_header* )(packet+ETH_HEADER_LENGTH);    // print ip
        // ver_ihl = version + ihl -> &0x0f => word 32 bit -> *4 = Byte
        const struct tcp_header* tcp = (struct tcp_header*)(packet+ETH_HEADER_LENGTH+((ip->ver_ihl&0x0f)*4));
        u_char str[11] = {0};      // include NULL +1

        printf("#------------------------------------------------------------------------------\n");
        printf("[+] Ethernet Header\n");
        printf("    - SRC_MAC : ");
        printf_ethernet((uint8_t*)eth->src_mac);
        printf("    - DST_MAC : ");
        printf_ethernet((uint8_t*)eth->dst_mac);

        if(ntohs(eth->eth_type) == EHT_TYPE_IPv4){
            printf("\n    [+] IP Header\n");
            printf("        - SRC_IP : ");
            printf_ip((uint8_t*)ip->src_ip);
            printf("        - DST_IP : ");
            printf_ip((uint8_t*)ip->dst_ip);

            if(ip->ip_protocol == IP_PROTOCOL){
                printf("\n        [+] TCP Header\n");
                printf("            - SRC_PORT : ");
                printf_port((uint8_t*)tcp->src_port);
                printf("            - DST_PORT : ");
                printf_port((uint8_t*)tcp->dst_port);

                uint32_t data_length = (header->len)-ETH_HEADER_LENGTH-(((ip->ver_ihl)&0x0f)*4)-((((tcp->Hlen)&0xf0)>>4)*4);
                const u_char* packet_count = packet + ETH_HEADER_LENGTH+(((ip->ver_ihl)&0x0f)*4)+((((tcp->Hlen)&0xf0)>>4)*4);

                if(data_length>0 && tcp->tcp_flag != TCP_FLAG_PHS_ACK){
                    printf("\n            [+] Length\n");
                    printf("                - header->len : %d\n", header->len);
                    printf("                - ip->ver_ihl : %d\n", ((ip->ver_ihl)&0x0f)*4);
                    printf("                - tcp->Hlen  : %d\n", (((tcp->Hlen)&0xf0)>>4)*4);
                    printf("                - data_length : %d\n", data_length);
                    printf("\n            [=]This is Padding Data = ");

                    if(data_length > 10){
                        memcpy(str, packet_count, 11);

                        for(int i = 0; i < 10; i++){
                            printf("%02x ", str[i]);
                        }
                        printf("\n");
                    }
                    else{
                        memcpy(str, packet_count, data_length);

                        for(int i = 0; i < data_length; i++){
                            printf("%02x ", str[i]);
                        }
                        printf("\n");
                    }
                }

                else if(data_length>0 && tcp->tcp_flag == TCP_FLAG_PHS_ACK){
                    printf("\n                [+] Length\n");
                    printf("                    - header->len : %d\n", header->len);
                    printf("                    - ip->ver_ihl : %d\n", ((ip->ver_ihl)&0x0f)*4);
                    printf("                    - tcp->Hlen  : %d\n", (((tcp->Hlen)&0xf0)>>4)*4);
                    printf("                    - data_length : %d\n", data_length);
                    printf("\n                [=] Data = ");

                    if(data_length > 10){
                        memcpy(str, packet_count, 11);

                        for(int i = 0; i < 10; i++){
                            printf("%02x ", str[i]);
                        }
                        printf("\n");
                    }
                    else{
                        memcpy(str, packet_count, data_length);

                        for(int i = 0; i < data_length; i++){
                            printf("%02x ", str[i]);
                        }
                        printf("\n");
                    }
                }

                else {
                    printf("\n[-] Does not contain Data\n");
                    continue;
                }

            }

            else{
                printf("\n[-] This is not TCP\n");
                continue;
            }

        }

        else{
            printf("\n[-] This is not IPv4\n");
            continue;
        }
     }
    pcap_close(handle);
    return 0;
}
