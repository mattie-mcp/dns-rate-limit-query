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
    unsigned short id;          // identification number

    unsigned char rd :1;        // recursion desired
    unsigned char tc :1;        // truncated msg
    unsigned char aa :1;        // authoritative answer
    unsigned char opcode :4;    // op code
    unsigned char qr :1;        // query/response flag

    unsigned char rcode :4;     // r code
    unsigned char cd :1;        
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;

    unsigned short qd_count :16;     // number of question entries
    unsigned short an_count :16;   // number of answer entries
    unsigned short ns_count :16;  // number of authority entries
    unsigned short ar_count :16;   // number of resource records
};

int truncated_count;
int qtyreceived_count;
int qtyfailed_count;
typedef enum { false, true } boolean;
boolean debug;

/**
 * Function: query_callback
 * Callback after query is sent
 *
 * arg: itself
 * status: ares defined response status
 * timeouts: how many times query timed out
 * abuf: Result buffer, dns header. Failed query, abuf is null
 * alen: Length of abuf
 */
void query_callback(void* arg, int status, int timeouts, unsigned char *abuf, int alen){

	if (status == ARES_SUCCESS){
        struct DNS_HEADER *dns_hdr = (struct DNS_HEADER*) abuf;
        qtyreceived_count++;
        if (debug == true){
        	printf("success, packet is %i bytes\n", alen);
            printf("id num:                0x%X\n", dns_hdr->id);
            printf("op code:               %d\n", dns_hdr->opcode);
            printf("authoritative:         %d\n", dns_hdr->aa);
            printf("recursion desired:     %d\n", dns_hdr->rd);
            printf("recursion available:   %d\n", dns_hdr->ra);
            printf("query/response flag:   %d\n", dns_hdr->qr);
            printf("truncated response :   %d\n", dns_hdr->tc);
        }
        if (dns_hdr->tc == 1){
            truncated_count++;
        }
	}
	else {
        qtyfailed_count++;
    }
}

/**
 * Function: wait_ares
 * Waits for all pending queries on channel to be processed according to timeout val
 *
 * timeout: File descriptor read timeout (in ms)
 * channel: ares_channel to process
 */
static void wait_ares(int timeout, ares_channel channel)
{

    while(1){
        // declare timevals for timeouts and fd
        struct timeval *tvp, tv, *max_t;
        fd_set read_fds, write_fds;

        max_t = (struct timeval*) malloc(sizeof(struct timeval));
        max_t->tv_usec = (suseconds_t) timeout;

        // reset file descriptors
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
    
        // Gets file descriptors to process
        int nfds = ares_fds(channel, &read_fds, &write_fds);
        if(nfds == 0){
            break;
        }

        // maximum time we should wait
        tvp = ares_timeout(channel, max_t, &tv);

        // updates the file descriptors with timeout
        select(nfds, &read_fds, &write_fds, NULL, tvp);

        // handles pending queries on channel
        ares_process(channel, &read_fds, &write_fds);
    }
}

int main(int argc, char *argv[])
{
    debug = false;
    char *log_file;
    if (argc < 2){
		printf("Usage: client packets_to_send debug_mode[optional] file_output[optional]\n");
		exit(1);
	}
    if (argc == 3 && strcmp(argv[2],"true") == 0)
        debug = true;
    if (argc == 4 && argv[3])
        log_file = argv[3];

    /** ares initialization and options */
    ares_channel channel;
    struct ares_options options;
    int optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUT | ARES_OPT_TRIES;
	int status, i;
    int packetsToSend = atoi(argv[1]);

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }

    /* Should be sending only DNS packets with no extra processing */
    options.timeout = 10;            // timeout in s
    options.tries = 1;               //number of retries to send
    options.flags = ARES_FLAG_IGNTC; // can add option ARES_FLAG_NOCHECKRESP to keep refused responses
    
    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }
   
    /** Read in file */
//    FILE *f
    printf("sending %d packets...\n", packetsToSend);
	unsigned char **qbuf = malloc(sizeof(unsigned char **));
	int *buflen = malloc(sizeof( int*));
   
    /** Send queries */
    int timeout = 1000; // ms
	for ( i=0; i<packetsToSend; i++ ){
	    ares_create_query("example.local", ns_c_in, ns_t_a, i, 0, qbuf, buflen, 0);
		ares_send(channel, *qbuf, *buflen, query_callback, NULL);
	}

    wait_ares(timeout, channel);
    printf("received %d response(s), sent %d:\n", qtyreceived_count, packetsToSend);
    printf("\t| %d response(s) truncated\n", truncated_count);
    printf("\t| %d failed lookup(s) - no response\n", qtyfailed_count);

    /** Logs results */
    if (log_file) {
        //open file and print
        printf("printing to file... %s\n", log_file);
        FILE *f = fopen(log_file, "w+");
        fprintf(f, "responses,truncated,failed\n");
        fprintf(f, "%d,%d,%d", qtyreceived_count, truncated_count, qtyfailed_count);
        fclose(f);
    }

    /** Clean up */
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
}
