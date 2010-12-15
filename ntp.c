/* ntp.c - Network Time Protocol client
 * author: Eugene Ma (edma)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

#define NTP_VERSION 		0xe3
#define NTP_DEFAULT_PORT	"123"
#define SEC_IN_YEAR 		31556926
#define UNIX_OFFSET 		2208988800L
#define VN_BITMASK(byte) 	((byte & 0x3f) >> 3)
#define LI_BITMASK(byte) 	(byte >> 6)
#define MODE_BITMASK(byte) 	(byte & 0x7)
#define ENDIAN_SWAP32(data)  	((data >> 24) | /* right shift 3 bytes */ \
				((data & 0x00ff0000) >> 8) | /* right shift 1 byte */ \
			        ((data & 0x0000ff00) << 8) | /* left shift 1 byte */ \
				((data & 0x000000ff) << 24)) /* left shift 3 bytes */

struct ntpPacket {
	uint8_t flags;
	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	uint32_t root_delay;
	uint32_t root_dispersion;
	uint8_t referenceID[4];
	uint32_t ref_ts_sec;
	uint32_t ref_ts_frac;
	uint32_t origin_ts_sec;
	uint32_t origin_ts_frac;
	uint32_t recv_ts_sec;
	uint32_t recv_ts_frac;
	uint32_t trans_ts_sec;
	uint32_t trans_ts_frac;
} __attribute__((__packed__)); /* this is not strictly necessary,
				* structure follows alignment rules */

int main(int argc, char *argv[]) {
	char *server; /* no default server */
	char *port = NTP_DEFAULT_PORT;
	struct addrinfo hints, *res, *ap; /* address info structs */
	socklen_t addrlen = sizeof(struct sockaddr_storage);

	struct ntpPacket packet;
	uint8_t *ptr = (uint8_t *)(&packet); /* to read raw bytes */

	int server_sock; /* send through this socket */
	int error; /* error checking */
	int i;
	unsigned int recv_secs;

	time_t total_secs;
	struct tm *now;

	/* server is required, port is optional */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <server> [port]\n", argv[0]);
		exit(1);
	}
	server = argv[1];
	if (argc > 2)
		port = argv[2];

	memset(&packet, 0, sizeof(struct ntpPacket));
	packet.flags = NTP_VERSION;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;

	/* fill our address structs for ntp server */
	error = getaddrinfo(server, port, &hints, &res);
	/* error checking */
	if (error != 0) {
		fprintf(stderr, "getaddrinfo() error: %s", gai_strerror(error));
		exit(1);
	}
	/* loop through results */
	for (ap = res; ap != NULL; ap = ap->ai_next) {
		server_sock = socket(ap->ai_family, ap->ai_socktype, ap->ai_protocol);
		if (server_sock == -1)
			continue;
		break;
	}
	if (ap == NULL) {
		fprintf(stderr, "socket() error\n");
		exit(2);
	}

	error = sendto(server_sock, &packet, sizeof(struct ntpPacket), 0, ap->ai_addr, addrlen);
	if (error == -1) {
		fprintf(stderr, "sendto() error\n");
		exit(2);
	}
	error = recvfrom(server_sock, &packet, sizeof(struct ntpPacket), 0, ap->ai_addr, &addrlen);
	if (error == -1) {
		fprintf(stderr, "recvfrom() error\n");
		exit(2);
	}
	
	freeaddrinfo(res); /* all done */

	/* print raw bytes */
	for (i = 0; i < sizeof(struct ntpPacket); i++) {
		if (i != 0 && i % 8 == 0)
			printf("\n");
		printf("0x%2x ", ptr[i]);
	}
	printf("\n");

	/* correct for right endianess */
	packet.root_delay = ENDIAN_SWAP32(packet.root_delay);
	packet.root_dispersion = ENDIAN_SWAP32(packet.root_dispersion);
	packet.ref_ts_sec = ENDIAN_SWAP32(packet.ref_ts_sec);
	packet.ref_ts_frac = ENDIAN_SWAP32(packet.ref_ts_frac);
	packet.origin_ts_sec = ENDIAN_SWAP32(packet.origin_ts_sec);
	packet.origin_ts_frac = ENDIAN_SWAP32(packet.origin_ts_frac);
	packet.recv_ts_sec = ENDIAN_SWAP32(packet.recv_ts_sec);
	packet.recv_ts_frac = ENDIAN_SWAP32(packet.recv_ts_frac);
	packet.trans_ts_sec = ENDIAN_SWAP32(packet.trans_ts_sec);
	packet.trans_ts_frac = ENDIAN_SWAP32(packet.trans_ts_frac);

	/* print raw data */
	printf("LI: %u\n", LI_BITMASK(packet.flags));
	printf("VN: %u\n", VN_BITMASK(packet.flags));
	printf("Mode: %u\n", MODE_BITMASK(packet.flags));
	printf("stratum: %u\n", packet.stratum);
	printf("poll: %u\n", packet.poll);
	printf("precision: %u\n", packet.precision);
	printf("root delay: %u\n", packet.root_delay);
	printf("root dispersion: %u\n", packet.root_dispersion);
	printf("reference ID: %u.", packet.referenceID[0]);
	printf("%u.", packet.referenceID[1]);
	printf("%u.", packet.referenceID[2]);
	printf("%u\n", packet.referenceID[3]);
	printf("reference timestamp: %u.", packet.ref_ts_sec);
	printf("%u\n", packet.ref_ts_frac);
	printf("origin timestamp: %u.", packet.origin_ts_sec);
	printf("%u\n", packet.origin_ts_frac);
	printf("receive timestamp: %u.", packet.recv_ts_sec);
	printf("%u\n", packet.recv_ts_frac);
	printf("transmit timestamp: %u.", packet.trans_ts_sec);
	printf("%u\n", packet.trans_ts_frac);

	/* print date with receive timestamp */
	recv_secs = packet.recv_ts_sec - UNIX_OFFSET; /* convert to unix time */
	total_secs = recv_secs;
	printf("Unix time: %u\n", (unsigned int)total_secs);
	now = localtime(&total_secs);
	printf("%02d/%02d/%d %02d:%02d:%02d\n", now->tm_mday, now->tm_mon+1, \
		       	now->tm_year+1900, now->tm_hour, now->tm_min, now->tm_sec);

	return 0;
}
