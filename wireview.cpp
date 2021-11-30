
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

//Push test

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
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

    if(argc != 2){ fprintf(stdout,"Usage: %s numpackets\n",argv[0]);return 0;}

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }
    /* open device for reading */
    //descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    //we want to open, fro p2, offline instead!
    descr = pcap_open_offline(argv[1],errbuf);
    if(descr == NULL)
    { printf("pcap_open_offline(): %s\n",errbuf); exit(1); }

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
    return 0;
}
