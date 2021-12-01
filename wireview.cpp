
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


    static int count = 0;
    time_t rtime;
    suseconds_t rtimems;
    time_t rtimeLast;
    suseconds_t rtimemsLast;
#include <map>
#include <set>

using namespace std;
//Code shown in class on friday
static int count = 0;

//Push test

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;    /* pcap.h */
    struct ether_header *eptr; /* net/ethernet.h */
    u_char **des_adds;
    std::map<int, const u_char> packets;
/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
    void my_callback(u_char * useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
    {
        //fprintf(stdout,"%d, ",count);
        count++;
        fprintf(stdout, "Hello World: %d, ", count);
        fflush(stdout);
        packets.insert(std::pair<int, const u_char>(count,*packet));
    }

int main(int argc, char **argv)
{
    //if first packet get timestamp
    if(count == 0){
        fprintf(stdout,"Time Stamp: %d, ",pkthdr->ts.tv_sec);
        rtime = (time_t)pkthdr->ts.tv_sec;
        rtimems = (suseconds_t)pkthdr->ts.tv_usec;
        struct tm rstime;
    char       buf[100];
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
    fprintf(stdout,"Hello World: %d, ",count);
    fflush(stdout);
}

int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    

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
    pcap_loop(descr,10000,my_callback,NULL);
    
    //Printing packet capture time in seconds
    time_t elapsedSec = rtimeLast - rtime;
    suseconds_t elapsedMSec = rtimemsLast - rtimems;

    if(elapsedMSec < 0){
        elapsedSec-=1;
        elapsedMSec=1000000+elapsedMSec;
    }    

    timeval time_ourval =
    { .tv_sec = elapsedSec, .tv_usec = elapsedMSec };
    printf("Duration of the packet capture in seconds: %ld.%06ld\n", time_ourval.tv_sec, time_ourval.tv_usec);
    //Printing total number of packets
    fprintf(stdout,"Total Packets Processed: %d, ",count);
    fprintf(stdout,"\nDone processing packets... wheew!\n");
    pcap_loop(descr, 10000, my_callback, NULL);

    fprintf(stdout, "Total Packets Processed: %d, ", count);
    fprintf(stdout, "\nDone processing packets... wheew!\n");
   /*  if (ntoh(eptr->ether_type) == ETHERTYPE_IP)
    {
    }
    if (ntoh(eptr->ether_type) == ETHERTYPE_ARP)
    {
    } */
    //Ethernet parsing
    //loop through all packets. pointer arthmetic to parse

    set<const u_char> des_adds;
    set<const u_char> src_adds;
    for (int i = 0; i < count; i++)
    {
        const u_char *destination_address;
        const u_char *source_address;
        double len;
        char *data;
        //*packet + 8 for destination address
        const u_char *cur_address = packet + 8;
        destination_address = cur_address;
        //If unique add to list
        auto found = des_adds.find(*destination_address);
        if(found !=des_adds.end())
        {
            des_adds.insert(*destination_address);
            printf("New Destination: ", *destination_address);
        }
        //result + 6 for source address
        source_address = cur_address + 6;
        //If unique add to list
        found = src_adds.find(*source_address);
        if (found!= src_adds.end())
            {
                src_adds.insert(*source_address);
                printf("New Source: ", *source_address);
            }
        //result + 6 for length
        cur_address = source_address + 6;
        len = *cur_address;
        //result + 2 for data
        cur_address += 2;
        //parse data for length of length
        //Do we need the data? I don't think we need the data so I'm waiting on this?
        }

        return 0;
    }