#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <pcap/pcap.h>
#include "checksum.h"
#include <winsock2.h>


struct Ethernet{
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
};

void print_address(const u_char addr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void ethernet(const u_char *packet){

    struct Ethernet eth_head;
    memcpy(eth_head.dest, packet, 6);
    memcpy(eth_head.source, packet + 6, 6);
    memcpy(eth_head.type, packet + 12, 2);

    /*  Ethernet Header
            Dest MAC: ff:ff:ff:ff:ff:ff
	        Source MAC: 00:02:2d:90:75:89 <----- Style of print
	        Type: ARP*/

    printf("\tEthernet Header\n");

    printf("\t\tDest Mac: ");
    print_address(eth_head.dest);

    printf("\t\tSource Mac: ");
    print_address(eth_head.source);
    
    /*IP type -> 0x0800, ARP type -> 0x0806*/
    unsigned short eth_type = ntohs(eth_head.type);
    if (eth_type == 0x0806){
        printf("\t\tType: ARP");
    }
    else if (eth_type == 0x0800){
        printf("\t\tType: IP");
    }
    

    

}
// struct IP{
//     uint8_t Serv_Type; //type of service
//     uint16_t len; //total length
//     uint16_t id; //identification
//     uint8_t version; //version ipv4 or 6
//     uint16_t flags; //flags + offset
//     uint8_t ttl; //time to live
//     uint8_t protocol; //protocol
//     uint16_t checksum; //checksum
//     uint32_t source; // src address
//     uint32_t dest; //destination

// };

// struct ARP{

// };

// struct ICMP{

// };

// struct TCP{

// };

// struct UDP{

// };

int main (int argc, char *argv[]){

}