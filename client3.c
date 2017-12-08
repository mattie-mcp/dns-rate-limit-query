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
#include <time.h>
#include <pthread.h>

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

struct lookup_record {
    char *domain_name;
    char *dns_name;
    char *alt_domain_name;
    int qty_received;
    int qty_truncated;
    int qty_failed;
};

struct lookup_record **queries;
int server_count = 0;
struct ares_options options;
int packet_id=0;

void setup_c_ares();
void read_file(char *file_name, struct lookup_record **queries);
void get_dns(ares_channel channel, struct lookup_record *record);
void send_packet(ares_channel channel, struct lookup_record *record);
FILE *log_filep;
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
    
    struct lookup_record *record = (struct lookup_record*) arg;
    //printf("Status: %d\n", status);
	if (status == ARES_SUCCESS){
        struct DNS_HEADER *dns_hdr = (struct DNS_HEADER*) abuf;
        record->qty_received++;
        if (dns_hdr->tc == 1){
            record->qty_truncated++;
        }
	}
	else {
        record->qty_failed++;
    }
}

/**
 * Function: dnslookup_callback
 * Callback after dns lookup query is sent
 *
 * arg: itself
 * status: ares defined response status
 * timeouts: how many times query timed out
 * abuf: Result buffer, dns header. Failed query, abuf is null
 * alen: Length of abuf
 */
void dnslookup_callback(void* arg, int status, int timeouts, unsigned char *abuf, int alen){
    struct lookup_record *record = (struct lookup_record*) arg;

    if (status == ARES_SUCCESS) {
        struct hostent  *host;// = malloc(sizeof(struct hostent));
        int status;

        if ((status = ares_parse_ns_reply(abuf, alen, &host)) != ARES_SUCCESS && log_filep != NULL) {
        //    fprintf(log_filep, "[error] parsing reply failed %s: %s\n", record->domain_name, ares_strerror(status));
        //    fflush(log_filep);
        }
        else {
            record->dns_name = (char*) malloc(strlen(host->h_aliases[0])+1);
            strcpy(record->dns_name, host->h_aliases[0]);
            ares_free_hostent(host);
        }
    }
}

/**
 * Function: wait_ares
 * Waits for all pending queries on channel to be processed according to timeout val
 *
 * timeout: File descriptor read timeout (in ms)
 * channel: ares_channel to process
 */
static void wait_ares(int timeout, ares_channel channel) {
    while(1){
        // declare timevals for timeouts and fd
        struct timeval *tvp, tv, max_t;
        fd_set read_fds, write_fds;

        max_t.tv_usec = (suseconds_t) timeout;

        // reset file descriptors
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
    
        // Gets file descriptors to process
        int nfds = ares_fds(channel, &read_fds, &write_fds);
        if(nfds == 0){
            break;
        }

        // maximum time we should wait
        tvp = ares_timeout(channel, &max_t, &tv);

        // updates the file descriptors with timeout
        select(nfds, &read_fds, &write_fds, NULL, tvp);

        // handles pending queries on channel
        ares_process(channel, &read_fds, &write_fds);
    }
}

static void short_wait_ares(int timeout, ares_channel channel) {
    while(1){
        // declare timevals for timeouts and fd
        struct timeval *tvp, tv, max_t;
        fd_set read_fds, write_fds;

        max_t.tv_usec = (suseconds_t) timeout;

        // reset file descriptors
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        // Gets file descriptors to process
        int nfds = ares_fds(channel, &read_fds, &write_fds);
        if(nfds == 0){
            break;
        }

        // maximum time we should wait
        tvp = ares_timeout(channel, &max_t, &tv);

        // updates the file descriptors with timeout
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        struct timeval tmp;
        tmp.tv_sec=0;
        tmp.tv_usec=0;
        int n = select(nfds, &read_fds, NULL, NULL, &tmp);
        if(n==0){
         break;
        }

        // handles pending queries on channel
        ares_process(channel, &read_fds, &write_fds);
     }
}

void free_mem(struct lookup_record *record) {
    if (record->dns_name != NULL)
        free(record->dns_name);
    free(record);
}

int main(int argc, char *argv[]) {
    char *log_file;
    if (argc < 3){
		printf("Usage: client [packets_to_send] [file_to_red] [file_output (optional)]\n");
		exit(1);
	}
    if (argc == 4 && argv[3])
        log_file = argv[3];

    int packetsToSend = atoi(argv[1]);
    char *fileToRead = argv[2];

    setup_c_ares();

    /* Should be sending only DNS packets with no extra processing */
    options.timeout = 1000;            // timeout in ms
    options.tries = 1;               //number of retries to send
    options.flags = ARES_FLAG_IGNTC; // can add option ARES_FLAG_NOCHECKRESP to keep refused responses
    /** ares initialization and options */
    int optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

    struct lookup_record *queries[101000];
    /** Read in file and save */
    printf("[info] reading in file\n");
    read_file(fileToRead, queries);
    if (log_file) {
        log_filep = fopen(log_file, "w+");
        fprintf(log_filep, "status domain_name dns_name dns_ip queries_sent responses_received responses_truncated responses_failed\n");
    }

    printf("[info] read in file, sending requests...\n");
    
    /** Send queries */
    int q;
    for ( q=0; q<server_count; q++ ) {
        struct lookup_record *record = queries[q];

        if ((q % 50) == 0) {
            printf("[info] on query %d of %d\n", q, server_count);
        }
        //printf("Testing %s, %s\n", record.dns_name, record.domain_name);
        ares_channel channel;

        int status = ares_init_options(&channel, &options, optmask);
        if ( status != ARES_SUCCESS ) {
            printf("[error] could not initialize channel\n");
            fprintf(log_filep, "[error] could not initialize for %s channel, skipping\n", record->dns_name);
            fflush(log_filep);
            return 1;
        }
        if (record->dns_name==NULL) {
            get_dns(channel, record);
            wait_ares(options.timeout, channel);
        }
        // make sure get_dns was a success
        if (record->dns_name == NULL || strcmp(record->dns_name, "") == 0) {
            // in case it's a subdomain, lookup again
            char *tmp =  malloc(strlen(record->domain_name)+1);
            strcpy(tmp,record->domain_name);
            strtok(tmp, ".");
	    //free(tmp);
            record->alt_domain_name = strtok(NULL, "");
            get_dns(channel, record);
            wait_ares(options.timeout, channel);
            // if it's still a failure, skip
            if (record->dns_name == NULL || strcmp(record->dns_name, "") == 0) {
                fprintf(log_filep, "[error] could not find dns server of %s, skipping\n", record->domain_name);
                fflush(log_filep);
                free_mem(record);
                continue;
          }
        }
        
        struct ares_addr_node server;
        server.family = AF_INET;
        server.next = NULL;
        struct hostent *host_record = gethostbyname(record->dns_name);
        if ( host_record == NULL ) {
            fprintf(log_filep, "[error] could not find addr of %s, skipping\n", record->dns_name);
            fflush(log_filep);
            free_mem(record);
            continue;
        }
        struct in_addr host_addr;
        memcpy(&host_addr.s_addr, host_record->h_addr,4);
        server.addr.addr4 = host_addr;
        int val;
        if ( (val = ares_set_servers(channel, &server)) != ARES_SUCCESS ) {
            fprintf(log_filep, "[error] Setting server for domain %s: %d\n", record->domain_name, val);
            fflush(log_filep);
            free_mem(record);
            continue;
        }

        struct timespec sleeptime;
        sleeptime.tv_sec=0;        /* seconds */
        sleeptime.tv_nsec=500;       /* nanoseconds */
        for ( val=0; val<packetsToSend; val++ ) {
            nanosleep(&sleeptime,NULL);    
            send_packet(channel, record);
            if (val % 100 == 0){
                short_wait_ares(10000, channel);
            }
        }
        wait_ares(100000, channel);
//was timeout*10000
        if (log_file) {
            fprintf(log_filep, "[info] %s %s %s %d %d %d %d\n", record->domain_name,
                                                    record->dns_name,
                                                    inet_ntoa(host_addr),
                                                    packetsToSend,
                                                    record->qty_received, 
                                                    record->qty_truncated, 
                                                    record->qty_failed);
            fflush(log_filep);
            free_mem(record);
        }
        
        ares_destroy(channel);
    }

   fflush(log_filep);
    /** Clean up */
   if (log_file) {
       fclose(log_filep);
   }
    ares_library_cleanup();
    printf("done\n\n");
    return 0;
}

void get_dns(ares_channel channel, struct lookup_record *record) {
    unsigned char *qbuf;
    int buflen;
    int status;
    char *lookup = record->domain_name;
    if (record->alt_domain_name)
        lookup = record->alt_domain_name;

    if ((status =ares_create_query(lookup, ns_c_in, ns_t_ns, ++packet_id, 1, &qbuf, &buflen, 0)) != ARES_SUCCESS) {
        printf("[error] error creating query: %s\n", ares_strerror(status));
    }
    ares_send(channel, qbuf, buflen, dnslookup_callback, record);
    ares_free_string(qbuf);
    return;
}

void read_file(char *file_name, struct lookup_record **queries ) {
    FILE *source = fopen(file_name, "r");
    if (!source || source == NULL) {
        printf("[error] could not open file");
        exit(1);
    }

    char newline[4096];
    char tmp[1024];
    char tmp2[1024];
    server_count = 0;
    while( NULL != fgets(newline,4096,source)){
        int numtokens = sscanf(newline,"%s %s",tmp,tmp2);
        if(numtokens==0){
          break;
        }
//while ( EOF != fscanf(source,"%s %s",tmp,tmp2)){
       // printf("%s %s %d\n",tmp, tmp2, numtokens);
struct lookup_record *record = (struct lookup_record*) malloc(sizeof(struct lookup_record));
        record->domain_name = strdup(tmp);
        record->dns_name=NULL;
        if(numtokens==2){
          record->dns_name = strdup(tmp2);
        }
        record->alt_domain_name = NULL;
        queries[server_count++] = record;
    }
    fclose(source);
}

void setup_c_ares() {
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("[error] ares_library_init: %s\n", ares_strerror(status));
        exit(1);
    }
}

void send_packet(ares_channel channel, struct lookup_record *record) {   
    unsigned char *qbuf; 
    int buflen;
    
    int err;
    if ( (err = ares_create_query(record->domain_name, ns_c_in, ns_t_a, ++packet_id, 0, &qbuf, &buflen, 0)) != ARES_SUCCESS ) {
        printf("[error] error creating query %d\n", err);
    }
    ares_send(channel, qbuf, buflen, query_callback, record);
    ares_free_string(qbuf);
}
