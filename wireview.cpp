
//Part of code from Martin Casado

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <map>
#include <set>
#include <linux/ip.h>
//derived from linux kernal header if_arp.h
struct arphdr
{
    __be16 ar_hrd;                  /* format of hardware address	*/
    __be16 ar_pro;                  /* format of protocol address	*/
    unsigned char ar_hln;           /* length of hardware address	*/
    unsigned char ar_pln;           /* length of protocol address	*/
    __be16 ar_op;                   /* ARP opcode (command)		*/
                                    /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
    unsigned char ar_sip[4];        /* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
    unsigned char ar_tip[4];        /* target IP address		*/
};

using namespace std;

static int count = 0;
time_t rtime;
suseconds_t rtimems;
time_t rtimeLast;
suseconds_t rtimemsLast;

//Code shown in class on friday
static int count = 0;

//Push test

int i;
char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *descr;
const u_char *packet;
struct pcap_pkthdr hdr;    /* pcap.h */
struct ether_header *eptr; /* c */
u_char **des_adds;
/* std::map<int, const u_char> packets;
map<int, int> lens; */
/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    //Ethernet Parsing
    packet += sizeof(struct ethhdr);
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
    {
        __be32 sourceAddress = 0, targetAddress = 0;
        struct iphdr *ip_header = (struct iphdr *)packet;
        sourceAddress = ip_header->saddr;
        targetAddress = ip_header->daddr;
        //Check if source or target are unique in a map struct...
        packet += sizeof(struct iphdr);
        struct udphdr *udp_hdr = (struct udphdr *)packet;
    }
    if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
    {
        //request or reply by looking at op field
        u_char *sourceMacAddress, *sourceIPAddress, *targetMacAddress, *targetIPAddress;
        struct arphdr *arp_header = (struct arphdr *)packet;
        if (arp_header->ar_op == 1)
        {
            //request 3 fields
            sourceMacAddress = arp_header->ar_sha;
            sourceIPAddress = arp_header->ar_sip;
            targetIPAddress = arp_header->ar_tip;
        }
        else
        {
            //reply 4 fields
            sourceMacAddress = arp_header->ar_sha;
            sourceIPAddress = arp_header->ar_sip;
            targetMacAddress = arp_header->ar_tha;
            targetIPAddress = arp_header->ar_tip;
        }
        //Check if source or target are unique in a map struct...
    }
    
    
    
    //if first packet get timestamp
    if (count == 0)
    {
        fprintf(stdout, "Time Stamp: %d, ", pkthdr->ts.tv_sec);
        rtime = (time_t)pkthdr->ts.tv_sec;
        rtimems = (suseconds_t)pkthdr->ts.tv_usec;
        struct tm rstime;
        char buf[100];
        // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
        rstime = *localtime(&rtime);
        strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &rstime);
        //printing timestamp of first packet
        printf("%s\n", buf);
        //fprintf(stdout,"Time Stamp: %d, ",gmtime(time));
    }
    //get timestamp of every packet so we know which one is last
    rtimeLast = (time_t)pkthdr->ts.tv_sec;
    rtimemsLast = (time_t)pkthdr->ts.tv_usec;
    //count packets
    count++;
    fprintf(stdout, "Hello World: %d, ", count);
    fflush(stdout);
/*     packets.insert(std::pair<int, const u_char>(count, *packet));
 */}
/* void unique(set<const u_char> list, const u_char address, const char *statement)
{
    auto found = list.find(address);
    if (found != list.end())
    {
        list.insert(address);
        printf(statement, address);
    }
}
void math(map<int, int> lengths)
{
    int min = lengths.at(0);
    int max = lengths.at(0);
    int ave = lengths.at(0);
    for (int i = 1; i < lengths.size(); i++)
    {
        if (lengths.at(i) < min)
        {
            min = lengths.at(i);
        }
        if (lengths.at(i) > max)
        {
            max = lengths.at(i);
        }
        ave += lengths.at(i);
    }
    printf("The smallest packet collected was size: ", min);
    printf("The biggest sized packet collected was size: ", max);
    ave /= lengths.size();
    printf("The average size of the packets collected is: ", ave); 
}*/

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        fprintf(stdout, "Usage: %s numpackets\n", argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    /* open device for reading */
    //descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    //we want to open, fro p2, offline instead!
    descr = pcap_open_offline(argv[1], errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */
    pcap_loop(descr, 10000, my_callback, NULL);

    //Printing packet capture time in seconds
    time_t elapsedSec = rtimeLast - rtime;
    suseconds_t elapsedMSec = rtimemsLast - rtimems;

    if (elapsedMSec < 0)
    {
        elapsedSec -= 1;
        elapsedMSec = 1000000 + elapsedMSec;
    }

    timeval time_ourval =
        {.tv_sec = elapsedSec, .tv_usec = elapsedMSec};
    printf("Duration of the packet capture in seconds: %ld.%06ld\n", time_ourval.tv_sec, time_ourval.tv_usec);
    //Printing total number of packets
    fprintf(stdout, "Total Packets Processed: %d, ", count);
    fprintf(stdout, "\nDone processing packets... wheew!\n");

    //Ethernet parsing
    //loop through all packets. pointer arthmetic to parse

    /* set<const u_char> des_adds;
    set<const u_char> src_adds;

    for (int i = 1; i <= count; i++)
    {
        packet = &packets.at(count);
        const u_char *destination_address;
        const u_char *source_address;
        double len;
        char *data;
        //*packet + 8 for destination address
        const u_char *cur_address = packet + 8;
        destination_address = cur_address;
        //If unique add to list
        unique(des_adds, *destination_address, "New Destination: ");

        //result + 6 for source address
        source_address = cur_address + 6;
        //If unique add to list
        unique(src_adds, *source_address, "New Source: ");

        //result + 6 for length
        cur_address = source_address + 6;
        len = *cur_address;
        lens.insert(std::pair<int, int>(i, len));
    }
    math(lens);
    return 0; */
}