
//Part of code from Martin Casado

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>



//Code shown in class on friday
    static int count = 0;

//Push test

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    //fprintf(stdout,"%d, ",count);
    if(count == 0){
        fprintf(stdout,"Time Stamp: %d, ",pkthdr->ts);
    }
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

     fprintf(stdout,"Total Packets Processed: %d, ",count);
    fprintf(stdout,"\nDone processing packets... wheew!\n");
    return 0;
}
