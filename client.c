#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>

#include "packet.h"

/**
 * Struct to store whether a packet has been ack'd or not
 */
typedef struct ack_packet {
    unsigned int is_ackd : 1;
    struct timeval timeout;
    Packet pkt;
} AckPacket;

struct sockaddr_in relay1_addr, relay2_addr;
int relay_sock = -1;

AckPacket buffer[WINDOW_SIZE];

int timeout_index;

int pkt_count = 0;

/**
 * Node Name: Name of the node where the event has happened
 * Possible values: CLIENT, SERVER, RELAY1, RELAY2
 * Event Type: S (SEND), R (RECV) , D (DROP), TO (TIME OUT), RE (Retransmission)
 * Timestamp: The time of the event (Since all four processes would be running
 *            on the same machine)
 * Packet Type: DATA, ACK
 * Seq No: Sequence number of the DATA and the ACK packet.
 * Source: The transmitter of the packet over a link
 *         Possible Values (CLIENT, SERVER, RELAY1, RELAY2)
 * Dest: The receiver of the packet over a link
 *       Possible Values (CLIENT, SERVER, RELAY1, RELAY2)
 * @param event_type    The name of the event
 * @param pkt           The packet which caused the event
 * @param dest          The destination of the packet
 */
void print_packet(char* event_type, char* pkt_type, int seq_no, char* src, char* dest) {
    /* compute timestamp */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long min = tv.tv_sec / 60;
    long hr = (min / 60) % 60;
    char time_str[16];
    sprintf(time_str, "%02ld:%02ld:%02ld.%06ld", hr, (min % 60), (tv.tv_sec) % 60, tv.tv_usec);
    
    /* print details */
    printf("CLIENT\t%s\t%s\t%s\t%d\t%s\t%s\n", event_type, time_str, pkt_type, seq_no, src, dest);
}

/**
 * Displays an error message and terminates the program
 * @param err_msg   The error message
 */
void report_error(char* err_msg) {
    perror(err_msg);
    printf("Terminating program\n");
    exit(0);
}

/**
 * Creates a UDP socket and address structure
 * @param port  The port number to use for the connection
 * 
 * @return The newly created UDP socket
 */
void create_udp_socket(char* ip, int port, struct sockaddr_in* addr) {
    if(relay_sock == -1) {
        /* create socket */
        relay_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(relay_sock < 0) {
            report_error("Failed to create socket");
        }

        /* create address structure for port binding */
        struct sockaddr_in src;
        memset(&src, 0, sizeof(struct sockaddr_in));
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl(INADDR_ANY);
        src.sin_port = htons(CLIENT_PORT);

        /* bind port */
        if(bind(relay_sock, (struct sockaddr*) &src, sizeof(struct sockaddr_in)) < 0) {
            report_error("Failed to bind port");
        }
    }

    /* create destination address structure */
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(ip);
    addr->sin_port = htons(port);
}

/**
 * Creates and returns a new packet
 * @param ftpr  Input file pointer
 * 
 * @return new packet
 */
Packet create_packet(FILE* fptr) {
    Packet pkt;
    pkt.seq_no = ftell(fptr);
    pkt.payload_size = fread(pkt.payload, 1, PACKET_SIZE, fptr);
    if(pkt.payload_size < PACKET_SIZE) {
        pkt.is_last = 1;
    }
    if(pkt_count%2 == 0) {
        pkt.relay_no = 0;
    } else {
        pkt.relay_no = 1;
    }
    pkt_count = (pkt_count + 1) % 2;
    return pkt;
}

/**
 * Inserts new packets into the buffer till either the buffer is full
 * or the last packet to be sent is generated
 * @param fptr      Input file pointer
 * @param start     The start index from where buffer should be filled
 */
void insert_new_packets(FILE* fptr, int start) {
    int i;
    int is_last = 0;
    for(i = start; (i < WINDOW_SIZE) && (is_last == 0); i++) {
        AckPacket pkt;
        pkt.is_ackd = 0;
        pkt.timeout.tv_sec = RETRANSMISSION_TIMEOUT;
        pkt.timeout.tv_usec = 0;
        pkt.pkt = create_packet(fptr);
        buffer[i] = pkt;
        is_last = pkt.pkt.is_last;
    }
}

/** 
 * Scans the given buffer of packets and returns the index of the
 * packet having smallest timeout value
 * 
 * @return The index of the packet having smallest timeout value
 */
int min_timeout() {
    int i;
    size_t min = __LONG_LONG_MAX__;
    for(i = 0; i < WINDOW_SIZE; i++) {
        if(buffer[i].is_ackd == 0) {
            min = (min < (buffer[i].timeout.tv_sec * 1000000 + buffer[i].timeout.tv_usec)) ? min : i;
        }
        if(buffer[i].pkt.is_last == 1) {
            break;
        }
    }
    return min;
}

/**
 * Sends the packet at the specified index to the server
 */
void send_packet(int index) {
    if(buffer[index].pkt.relay_no == 0) {
        if(sendto(relay_sock, &(buffer[index].pkt), sizeof(Packet), 0, (struct sockaddr*) &relay2_addr, sizeof(struct sockaddr_in)) < 0 && errno != EINTR) {
            report_error("Failed to send packet to server");
        }
    } else {
        if(sendto(relay_sock, &(buffer[index].pkt), sizeof(Packet), 0, (struct sockaddr*)  &relay1_addr, sizeof(struct sockaddr_in)) < 0 && errno != EINTR) {
            report_error("Failed to send packet to server");
        }
    }
}

/**
 * Sends all the new packets of the buffer to the server
 * @param start The starting index of the new packets in the buffer
 */
void send_all_packets(int start) {
    int i;
    for(i = start; i < WINDOW_SIZE; i++) {
        send_packet(i);
        
        print_packet("S", "DATA", buffer[i].pkt.seq_no, "CLIENT", ((buffer[i].pkt.relay_no == 0) ? "RELAY2" : "RELAY1"));
    }
}

/**
 * Updates the remaining time till timeout for a packet
 * @param timeout       Struct containing the time till timeout
 * @param time_taken    Time taken by current execution plan
 */
void update_packet_timeout(struct timeval* timeout, double time_taken) {
	double remaining_time = timeout->tv_sec + (double) timeout->tv_usec / CLOCKS_PER_SEC;
	remaining_time -= time_taken;
	long remaining_sec = (long) remaining_time;
	long remaining_usec = (long) ((remaining_time - (double) remaining_sec) * CLOCKS_PER_SEC);
	if(remaining_sec < 0 || remaining_usec < 0) {
		/* directly retransmit packet instead; set time as new */
        timeout->tv_sec = RETRANSMISSION_TIMEOUT;
        timeout->tv_usec = 0;
	} else {
		timeout->tv_sec = (size_t) remaining_sec;
		timeout->tv_usec = (size_t) remaining_usec;
	}
}

/**
 * Cancels any existing alarms
 */
void cancel_alarms() {
    struct itimerval it_val;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    it_val.it_value.tv_sec = 0;
    it_val.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it_val, NULL);
}

/**
 * Updates the remaining time for all packets in the buffer
 * @param elapsed_time  The time taken since last update
 */
void update_buffer_timeouts(double elapsed_time) {
    int i;
    for(i = 0; i < WINDOW_SIZE; i++) {
        if(buffer[i].is_ackd == 0) {
            /* packet waiting to be ACK'd, update it's timeout value */
            update_packet_timeout(&(buffer[i].timeout), elapsed_time);

            if(buffer[i].is_ackd == 0 && buffer[i].timeout.tv_sec == RETRANSMISSION_TIMEOUT && buffer[i].timeout.tv_usec == 0) {
                /* print packet timeout event */
                print_packet("TO", "DATA", buffer[i].pkt.seq_no, "CLIENT", ((buffer[i].pkt.relay_no== 0) ? "RELAY2" : "RELAY1"));

                /* retransmit packet */
                send_packet(i);

                /* print retransmission event */
                print_packet("RE", "DATA", buffer[i].pkt.seq_no, "CLIENT", ((buffer[i].pkt.relay_no== 0) ? "RELAY2" : "RELAY1"));
            }
        }
        if(buffer[i].pkt.is_last == 1) {
            break;
        }
    }
}

/**
 * Updates the buffer by removing all ACK'd packets from the start, shifting all
 * existing packets from the first unACK'd packet till the end leftward, and filling
 * up the newly created space with more packets if applicable. Also sends all new
 * packets to the server
 * @param fptr      Input file pointer
 */
void update_buffer(FILE* fptr) {
    int size = WINDOW_SIZE;
    /* finding start of first unACK'd packet */
    int start;
    for(start = 0; start < size && buffer[start].is_ackd == 1 && buffer[start].pkt.is_last == 0; start++);

    if(buffer[start].pkt.is_last == 1) {
        size = start;
        if(buffer[start].is_ackd == 1) {
            /* all packets have been ACK'd */
            buffer[0] = buffer[start];
            return;
        }
    }

    /* removing all previous ACK'd entries, shifting other packets ahead */
    int i;
    for(i = 0; i + start < size; i++) {
        buffer[i] = buffer[start + i];
    }

    if(buffer[i + start - 1].pkt.is_last != 1) {
        /* add new packets if applicable */
        insert_new_packets(fptr, i);

        /* send new packets to server */
        send_all_packets(i);
    }
}

/**
 * Handler for SIGALRM; retransmits the packet which caused a timeout
 * @param signo The signal which invoked the handler (unused)
 */
void sigalrm_handler(int signo) {
    /* print timeout event */
    print_packet("TO", "DATA", buffer[timeout_index].pkt.seq_no, "CLIENT", ((buffer[timeout_index].pkt.relay_no== 0) ? "RELAY2" : "RELAY1"));
    
    /* retransmit packet */
    send_packet(timeout_index);
    
    /* print retransission event */
    print_packet("RE", "DATA", buffer[timeout_index].pkt.seq_no, "CLIENT", ((buffer[timeout_index].pkt.relay_no== 0) ? "RELAY2" : "RELAY1"));
    
    /* update timeout values */
    buffer[timeout_index].timeout.tv_usec = 0;
    buffer[timeout_index].timeout.tv_sec = RETRANSMISSION_TIMEOUT;

    /* find next packet having smallest timeout */
    timeout_index = min_timeout();

    /* set alarm to resend packet on timeout */
    struct itimerval it_val;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    it_val.it_value = buffer[timeout_index].timeout;
    setitimer(ITIMER_REAL, &it_val, NULL);
}

/**
 * Registers the acknowledgement of a packet
 * @param ack_seq_no    Sequence nommber of packet for which ACK is received
 */
void ack_packet(int ack_seq_no) {
    for(int i = 0; i < WINDOW_SIZE; i++) {
        if(buffer[i].pkt.seq_no == ack_seq_no) {
            buffer[i].is_ackd = 1;

            /* print ACK */
            print_packet("R", "ACK", ack_seq_no, ((buffer[i].pkt.relay_no== 0) ? "RELAY2" : "RELAY1"), "CLIENT");
            
            break;
        }
    }
}

int main() {
    /* create sockets to connect to relays */
    create_udp_socket(RELAY_1_IP, RELAY_1_CLIENT_TO_SERVER_PORT, &relay1_addr);
    create_udp_socket(RELAY_2_IP, RELAY_2_CLIENT_TO_SERVER_PORT, &relay2_addr);

    timeout_index = -1;

    /* open input file for reading */
    FILE* fptr = fopen("input.txt", "r");
    if(fptr == NULL) {
        report_error("The requested file could not be opened");
    }

    /* initialize buffer to null */
    memset(buffer, 0, WINDOW_SIZE);

    /* ensuring that pointer is at the start of the file */
    fseek(fptr, 0, SEEK_SET);

    /* setting up signal handler for SIGALRM */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);

    struct itimerval it_val;

    /* print headings */
    printf("Node Name\tEvent Type\tTimestamp\tPacket Type\tSeq. No.\tSource\tDestination\n");

    /* sleeping to give a chance to server and relay to start first */
    sleep(2);

    /* initial population and send */
    insert_new_packets(fptr, 0);

    /* send all packets */
    send_all_packets(0);

    while(!(buffer[0].pkt.is_last == 1 && buffer[0].is_ackd == 1)) {
        /* update buffer */
        update_buffer(fptr);

        /* find min timeout packet */
        timeout_index = min_timeout();

        /* set alarm for this index */
        it_val.it_value = buffer[timeout_index].timeout;
        it_val.it_interval.tv_sec = 0;
        it_val.it_interval.tv_usec = 0;

        if(it_val.it_value.tv_usec == 0 && it_val.it_value.tv_sec == 0) {
            /* IDEALLY SHOULD NOT BE REQUIRED */

            /* print timeout log */
            print_packet("TO", "DATA", buffer[timeout_index].pkt.seq_no, "CLIENT", ((buffer[timeout_index].pkt.relay_no == 0) ? "RELAY2" : "RELAY1"));

            /* instantly retransmit packet */
            send_packet(timeout_index);

            /* print retransmission log */
            print_packet("RE", "DATA", buffer[timeout_index].pkt.seq_no, "CLIENT", ((buffer[timeout_index].pkt.relay_no == 0) ? "RELAY2" : "RELAY1"));
        } else {
            setitimer(ITIMER_REAL, &it_val, NULL);
        }

        /* start timer for operation */
        size_t start = clock();

        /* receive ack from server */
        Packet ack;
        if(recv(relay_sock, &ack, sizeof(Packet), 0) < 0) {
            report_error("Failed to receive packet from server");
        }

        /* cancel any existing alarms */
        cancel_alarms();

        /* register ack */
        ack_packet(ack.seq_no);

        /* end timer for operation */
        size_t end = clock();
        double elapsed_time = ((double)(end - start))/CLOCKS_PER_SEC;

        /* update timeouts */
        update_buffer_timeouts(elapsed_time);
    }

    close(relay_sock);
    fclose(fptr);

    printf("\nFile transferred successfully\n");

    return 0;
}