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
#include <signal.h>

#include "packet.h"

pid_t pid;
struct sockaddr_in client_addr, serv_addr;
int client_sock, server_sock;
int odd_even;
Packet send_pkt;

/**
 * handler to gracefully terminate program on encountering SIGINT
 * @param signo Unused (value of the signal received)
 */
void sigint_handler(int signo) {
    if(pid != 0) {
        kill(pid, SIGINT);
    }
    exit(0);
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
 * @param relay_num     Relay identifier (1 or 2)
 * @param event_type    The name of the event
 * @param pkt           The packet which caused the event
 * @param dest          The destination of the packet
 */
void print_packet(int relay_num, char* event_type, char* pkt_type, int seq_no, char* src, char* dest) {
    /* compute timestamp */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long min = tv.tv_sec / 60;
    long hr = (min / 60) % 60;
    char time_str[16];
    sprintf(time_str, "%02ld:%02ld:%02ld.%06ld", hr, (min % 60), (tv.tv_sec) % 60, tv.tv_usec);
    
    /* print details */
    printf("RELAY%d\t%s\t%s\t%s\t%d\t%s\t%s\n", relay_num, event_type, time_str, pkt_type, seq_no, src, dest);
}

/**
 * Returns the current timestamp computed to millisecond precision, given
 * the current time in seconds + microseconds
 * @param sec   The current timestamp in seconds
 * @param usec  The current timestamp in micro-seconds
 * 
 * @return The current timestamp in millisecond precision
 */
// unsigned long time_in_millis(unsigned long sec, unsigned long usec) {
//     return (sec * 1000) + (usec / 1000);
// }

/**
 * Returns a random time delay to be applied, dustributed uniformly
 * between 0 and 2000 milliseconds
 *
 * @return Time delay between 9 to 2000 milliseconds
 */
unsigned long delay_time() {
    return rand() % 2001;
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
 * randomly generates either 0, indicating accept, or 
 * generates 1, indicating drop. The rate is determined
 * by the rate specified in the macro PACKET_DROP_RATE
 */
int accept_or_drop() {
	int rand_till_100 = rand() % 100;
	return ((rand_till_100 < PACKET_DROP_RATE) ? 1 : 0);
}

/**
 * Creates a UDP socket bound to the host's IPv4 and PORT
 * @param ip            The IP address of host
 * @param local_port    The port number to use for locally receiving data
 * 
 * @return a new UDP socker
 */
int create_udp_socket(char* ip, int local_port) {
    /* create socket */
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) {
        report_error("Failed to create socket");
    }

    /* creating address structure for port binding */
    struct sockaddr_in src;
    memset(&src, 0, sizeof(struct sockaddr_in));
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(INADDR_ANY);
    src.sin_port = htons(local_port);

    /* binding port */
    if(bind(sock, (struct sockaddr*) &src, sizeof(struct sockaddr_in)) < 0) {
        report_error("Failed to bind port");
    }

    return sock;
}

/**
 * Creates an address structure for a given IPv4 address and PORT
 * @param ip    The IP address of destination
 * @param port  The listening port of destination
 * 
 * @return A new address structure
 */ 
struct sockaddr_in create_dest_addr(char* ip, int port) {
    /* creating address structure for destination */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    return addr;
}

/**
 * Manages sending of packets to server according to delays
 * @param signo Unused (value of the signal received)
 */
void sigalrm_handler(int signo) {
    if(sendto(server_sock, &send_pkt, sizeof(Packet), 0, (struct sockaddr*) &serv_addr, sizeof(struct sockaddr_in)) < 0) {
        report_error("Failed to send DATA to server");
    }

    /* print sending logs */
    print_packet(odd_even, "S", "DATA", send_pkt.seq_no, ((odd_even == 0) ? "RELAY2" : "RELAY1"), "SERVER");
}

int main(int argc, char** argv) {
    if(argc < 2) {
        fprintf(stderr, "Expected one argument. Found %d\nUsage: ./relay <0 or 1>\nwhere 0 denotes even and 1 denotes odd.", (argc - 1));
        exit(0);
    }

    odd_even = atoi(argv[1]) % 2;

    /* set random seed for rand() */
    srand(time(0));
    
    if(odd_even == 0) {
        /* even, relay 2 */
        client_sock = create_udp_socket(RELAY_2_IP, RELAY_2_CLIENT_TO_SERVER_PORT);
        server_sock = create_udp_socket(RELAY_2_IP, RELAY_2_SERVER_TO_CLIENT_PORT);
    } else {
        /* odd, relay 1 */
        client_sock = create_udp_socket(RELAY_1_IP, RELAY_1_CLIENT_TO_SERVER_PORT);
        server_sock = create_udp_socket(RELAY_1_IP, RELAY_1_SERVER_TO_CLIENT_PORT);
    }

    client_addr = create_dest_addr(CLIENT_IP, CLIENT_PORT);
    serv_addr = create_dest_addr(SERVER_IP, SERVER_PORT);

    /* setting a signal handler for SIGINT */
    signal(SIGINT, sigint_handler);

    /* ignoring status of child processes, to prevent formation of zombie processes */
    signal(SIGCHLD,SIG_IGN);

    /* print headings */
    printf("Node Name\tEvent Type\tTimestamp\tPacket Type\tSeq. No.\tSource\tDestination\n");

    if((pid = fork()) < 0) {
        report_error("Failed to create child process");
    } else if(pid == 0) {
        /* child process: listen for ACKs from server and send to client */
        Packet pkt;
        while(1) {
            int slen;
            if(recv(server_sock, &pkt, sizeof(Packet), 0) < 0) {
                report_error("Failed to receive ACK from server");
            }

            /* print receiving packet */
            print_packet(odd_even, "R", "ACK", pkt.seq_no, "SERVER", ((odd_even == 0) ? "RELAY2" : "RELAY1"));

            /* send ACK to client */
            if(sendto(client_sock, &pkt, sizeof(Packet), 0, (struct sockaddr*) &client_addr, sizeof(struct sockaddr_in)) < 0) {
                report_error("Failed to send ACK to client");
            }

            /* print sending log */
            print_packet(odd_even, "S", "ACK", pkt.seq_no, ((odd_even == 0) ? "RELAY2" : "RELAY1"), "CLIENT");

            if(pkt.is_last) {
                printf("\nFile transfer has been completed. Terminating relay\n");
                /* server indicated termination, terminate relays */
                kill(getppid(), SIGINT); /* parent will initiate termination of child, perform cleanup, and exit */
            }
        }
    } else {
        /* listen for packets from client and send to server */

        Packet pkt;

        while(1) {
            /* continuously receive packets from client */
            int slen;
            if(recv(client_sock, &pkt, sizeof(Packet), 0) < 0 && errno != EINTR) {
                report_error("Failed to receive packet from client");
            }

            /* either randomly drop a packet or enqueue it to be sent after delay */
            if(accept_or_drop() != 1) {
                // enqueue_packet(pkt);

                pid_t send_pid;
                if((send_pid = fork()) < 0) {
                    report_error("Failed to create child for sending packet");
                } else if(send_pid == 0) {
                    /* child process sends packet after some delay */
                    signal(SIGALRM, sigalrm_handler);
                    send_pkt = pkt;
                    struct itimerval it_val;
                    it_val.it_interval.tv_sec = 0;
                    it_val.it_interval.tv_usec = 0;
                    it_val.it_value.tv_sec = 0;
                    it_val.it_value.tv_usec = delay_time();
                    setitimer(ITIMER_REAL, &it_val, NULL);

                    pause();

                    return 0;
                } else {
                    /* print received packet log */
                    print_packet(odd_even, "R", "DATA", pkt.seq_no, "CLIENT", ((odd_even == 0) ? "RELAY2" : "RELAY1"));
                }
            } else {
                /* print dropped packet */
                print_packet(odd_even, "D", "DATA", pkt.seq_no, "CLIENT", ((odd_even == 0) ? "RELAY2" : "RELAY1"));
            }
        }
    }

    /* should be unreachable */
    close(client_sock);
    close(server_sock);
    return 0;
}