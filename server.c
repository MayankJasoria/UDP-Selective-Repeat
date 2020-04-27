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

int relay_sock = -1;
char buffer[(WINDOW_SIZE * PACKET_SIZE) + 1];
int expected_seq = 0;

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
 * Creates a new UDP socket, and binds it to server port
 * 
 * @return The newly created UDP socket
 */
void create_udp_socket() {
    if(relay_sock == -1) {
        relay_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(relay_sock < 0) {
            report_error("Failed to create socket");
        }
    }

    struct sockaddr_in src;
    memset(&src, 0, sizeof(struct sockaddr_in));
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(INADDR_ANY);
    src.sin_port = htons(SERVER_PORT);

    if(bind(relay_sock, (struct sockaddr*) &src, sizeof(struct sockaddr_in)) < 0) {
        report_error("Failed to bind port to socket");
    }
}

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
    printf("SERVER\t%s\t%s\t%s\t%d\t%s\t%s\n", event_type, time_str, pkt_type, seq_no, src, dest);
}

/**
 * Creates an acknowledgement packet for a given sequence number
 * @param seq_no     The sequence number of the packet which is to be ACK'd
 * @param relay_addr The address of the relay to be used for sending ACK
 *
 * @return ACK packet for the given sequence number
 */
Packet create_ack(int seq_no, int is_last, struct sockaddr_in* relay_addr) {
    Packet pkt;
    strcpy(pkt.payload, "");
    pkt.payload_size = 0;
    pkt.seq_no = seq_no;
    pkt.is_last = is_last;

    int relay_to_use = rand() % 2;

    relay_addr->sin_family = AF_INET;
    relay_addr->sin_addr.s_addr = inet_addr((relay_to_use == 0) ? RELAY_2_IP : RELAY_1_IP);
    relay_addr->sin_port = htons((relay_to_use == 0) ? RELAY_2_SERVER_TO_CLIENT_PORT : RELAY_1_SERVER_TO_CLIENT_PORT);

    return pkt;
}

/**
 * Removes in-sequence packets from the buffer, shifts other packets
 * (and holes for yet-to-be-received packets) to leftmost end
 */
void update_buffer() {
    /* finding new start of buffer */
    int next_start = strlen(buffer);
    int i;
    for(i = 0; i + next_start < (WINDOW_SIZE * PACKET_SIZE); i++) {
        buffer[i] = buffer[i+ next_start] ;
    }

    /* clearing remaining buffer */
    memset(buffer + i, '\0', (WINDOW_SIZE * PACKET_SIZE) - i);
}

/* debugging */
void print_buffer() {
    printf("\nPrinting Buffer at expected sequence number %d:\n", expected_seq);
    for(int i = 0; i < (WINDOW_SIZE * PACKET_SIZE) + 1; i++) {
        printf("%c", buffer[i]);
    }
    printf("\nBuffer printed\n");
}

int main() {
    /* setting seed for rand() */
    srand(time(0));

    /* create UDP socket */
    create_udp_socket();

    memset(buffer, '\0', (WINDOW_SIZE * PACKET_SIZE) + 1);

    /* print headings */
    printf("Node Name\tEvent Type\tTimestamp\tPacket Type\tSeq. No.\tSource\tDestination\n");

    int last_seq_no = __INT_MAX__;
    int is_last_ack = 0;

    /* open output file */
    FILE* fptr = fopen("output.txt", "w");
    fseek(fptr, 0, SEEK_SET);

    while(is_last_ack == 0) {
        Packet pkt;
        if(recv(relay_sock, &pkt, sizeof(Packet), 0) < 0) {
            report_error("Failed to receive packet from client");
        }

        /* print received packet */
        print_packet("R", "DATA", pkt.seq_no, ((pkt.relay_no == 0) ? "RELAY2" : "RELAY1"), "SERVER");

        if(pkt.seq_no == expected_seq) {
            /* write payload to buffer */
            strncpy(buffer, pkt.payload, pkt.payload_size);

            /* write buffer to file */
            fprintf(fptr, "%s", buffer);

            /* update expected sequence number */
            expected_seq += strlen(buffer);

            /* check if all packets have been received */
            if(expected_seq >= last_seq_no) {
                is_last_ack = 1;
            }

            /* send acknowledgement */
            struct sockaddr_in relay_addr;
            Packet ack = create_ack(pkt.seq_no, is_last_ack, &relay_addr);
            if(sendto(relay_sock, &ack, sizeof(Packet), 0, (struct sockaddr*) &relay_addr, sizeof(struct sockaddr_in)) < 0) {
                report_error("Failed to send acknowledgement to client");
            }

            /* print acknowledgement */
            print_packet("S", "ACK", ack.seq_no, "SERVER", ((ack.relay_no == 0) ? "RELAY2" : "RELAY1"));

            /* update buffer */
            update_buffer();

            /* debugging */
            print_buffer();
        } else if(pkt.seq_no > expected_seq && pkt.seq_no - expected_seq <= ((WINDOW_SIZE - 1) * PACKET_SIZE)) {
            /* send acknowledgement */
            struct sockaddr_in relay_addr;
            Packet ack = create_ack(pkt.seq_no, is_last_ack, &relay_addr);
            if(sendto(relay_sock, &ack, sizeof(Packet), 0, (struct sockaddr*) &relay_addr, sizeof(struct sockaddr_in)) < 0) {
                report_error("Failed to send acknowledgement to client");
            }

            /* print acknowledgement */
            print_packet("S", "ACK", ack.seq_no, "SERVER", ((ack.relay_no == 0) ? "RELAY2" : "RELAY1"));

            /* write packet to buffer */
            int index = pkt.seq_no - expected_seq;
            strncpy(buffer + index, pkt.payload, pkt.payload_size);

            /* debugging */
            print_buffer();
        } else {
            /* drop packet */
            print_packet("D", "DATA", pkt.seq_no, ((pkt.relay_no == 0) ? "RELAY2" : "RELAY1"), "SERVER");
        }
    }

    fclose(fptr);
    close(relay_sock);

    printf("\nFile received successfully, saved as output.txt\n");

    return 0;
}