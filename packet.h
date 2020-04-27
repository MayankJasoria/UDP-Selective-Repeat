#define SERVER_IP "127.0.0.1" /* Using loopback address for simplicity */
#define CLIENT_IP "127.0.0.1"
#define RELAY_1_IP "127.0.0.1"
#define RELAY_2_IP "127.0.0.1"

#define PACKET_SIZE 100 /* in bytes */
#define RETRANSMISSION_TIMEOUT 5 /* seconds */
// #define MAX_RETRIES 10 /* if exceeded, assume channel has been broken */

#define SERVER_PORT 12500
#define RELAY_1_CLIENT_TO_SERVER_PORT 12300
#define RELAY_1_SERVER_TO_CLIENT_PORT 12400
#define RELAY_2_CLIENT_TO_SERVER_PORT 12100
#define RELAY_2_SERVER_TO_CLIENT_PORT 12200
#define CLIENT_PORT 12000

#define PACKET_DROP_RATE 10

#define WINDOW_SIZE 5 /* in terms of number of packets */

typedef struct packet {
    unsigned long payload_size;
	unsigned int seq_no;
    unsigned int relay_no : 1; /* 0 -> relay 2, 1 -> relay 1 */
    unsigned int is_last : 1;
    char payload[PACKET_SIZE];
} Packet;