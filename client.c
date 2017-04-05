#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/nameser.h>
#include <sys/time.h>

struct DNS_HEADER{
    unsigned short id :16;          // identification number

    unsigned char aa :1;        // authoritative answer
    unsigned char tc :1;        // truncated msg
    unsigned char rd :1;        // recursion desired
    unsigned char ra :1;        // 
    unsigned char z :3;        // query/response flag

    unsigned char qr :1;        // query/response flag
    unsigned char opcode :4;    // purpose of msg

    unsigned char rcode :4;     // r code

    unsigned short qd_count :16;     // number of question entries
    unsigned short an_count :16;   // number of answer entries
    unsigned short ns_count :16;  // number of authority entries
    unsigned short ar_count :16;   // number of resource records
};

int truncated_count;
int qtyreceived_count;

void query_callback(void* arg, int status, int timeouts, unsigned char *abuf, int alen){
	if (status == ARES_SUCCESS){
        struct DNS_HEADER *dns_hdr = (struct DNS_HEADER*) abuf;
        qtyreceived_count++;
	//	 printf("success, packet is %i bytes\n", alen);
         printf("id num:        0x%X\n", dns_hdr->id);
         printf("op code:       0x%X\n", dns_hdr->opcode);
         printf("authoritative: 0x%X\n", dns_hdr->aa);
		 printf("truncated response : %d\n", dns_hdr->tc);
        if (dns_hdr->tc == 1){
      //      printf("truncated reponse\n");
            //printf("id num: %d\n", dns_hdr->id);
            truncated_count++;
        }
        
	}
	else
		printf("lookup failed: %d\n", status);
}

static void wait_ares(ares_channel channel)
{
    int timeout = 5;
    for(;;){
        struct timeval *tvp, tv, *max_t;
        fd_set read_fds, write_fds;
        int nfds;

        max_t->tv_usec = (suseconds_t) timeout;
       
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if(nfds == 0){
            break;
        }
        tvp = ares_timeout(channel, max_t, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2){
		printf("Usage: client packets_to_send\n");
		exit(1);
	}

    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
	int status, i;
    int packetsToSend = atoi(argv[1]);

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }
    options.timeout = 1000; // timeout in ms
    options.tries = 0;  //number of retries to send
    options.flags = ARES_FLAG_IGNTC;

    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }
    
    printf("ares initialized, sending %d packets\n", packetsToSend);
	unsigned char **qbuf = malloc(sizeof(unsigned char **));
	int *buflen = malloc(sizeof( int*));
//    clock_t start, end;
//    start = clock();
	for ( i=0; i<packetsToSend; i++ ){
        if ( i % 500 == 0)
            printf("message count: %d\n", i);
        // printf("creating query...\n"); // ns_c_in = 1 (internet); ns_t_a = 1 (host addr)
	    ares_create_query("example.local", ns_c_in, ns_t_a, i, 0, qbuf, buflen, 0);
		ares_send(channel, *qbuf, *buflen, query_callback, NULL);
//		wait_ares(channel);
	}
//    end = (int) (clock()-start) / CLOCKS_PER_SEC;
    printf("sent %d packets\n", packetsToSend);	

    wait_ares(channel);

    printf("received %d packets     | %d were truncated\n", qtyreceived_count, truncated_count);

    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
}
