/*

tftp - trivial file transfer client

*/

#if OS == LINUX
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* basename(3) (-std=c11) */
#include <libgen.h>

#include "tftp.h"
#include "auxnet.h"
#include "auxmath.h"

#ifdef DEBUG
#include "iso_iec_646.h"
#endif

char *log_priority[] =
{
	"emerg",		/* LOG_EMERG */
	"alert",		/* LOG_ALERT */
	"crit",			/* LOG_CRIT */
	"err",			/* LOG_ERR */
	"warning",		/* LOG_WARNING */
	"notice",		/* LOG_NOTICE */
	"info",			/* LOG_INFO */
	"debug",		/* LOG_DEBUG */
	NULL
};

#define XFRIN			0
#define XFROUT			1

/* The default values for these are defined below. */
#define BUFFER_SZ 		(pkt_hdr_sz + pkt_data_sz)

/* Recycle the variables for use with an error packet. Make the code more readable. */
#define recv_errorcode	recv_block
#define recv_errmsg		recv_mode

void dump_pkt(char *pkt, int direction, ssize_t pkt_sz);
void _log_msg(int priority, const char *msg, va_list args);
void log_msg(int priority, const char *msg, ...);
void exit_fail(const char *msg, ...);
void exit_handler(void);
void close_s(int *s, char *name);
void signal_handler(int signal);
void usage(void);

void unpack_pkt(void);
int send_pkt(void);
int recv_pkt(void);
void WRQ(void);
void RRQ(void);
void transfer_core(void);

/* verify calls to free() = calls to malloc() */
#define DEBUG_MEMORY_VERBOSE
#ifdef DEBUG
#undef DEBUG_MEMORY_VERBOSE

int mem_count = 0;

void *Rmalloc(size_t size)
{
#ifdef DEBUG_MEMORY_VERBOSE
	log_msg(LOG_INFO, "malloc()");
#endif
	mem_count++;
	return malloc(size);
}

void Rfree(void *ptr)
{
#ifdef DEBUG_MEMORY_VERBOSE
	log_msg(LOG_INFO, "free()");
#endif
	mem_count--; free(ptr);
}

int Rmemory_get_count(void)
{
	return mem_count;
}

#define malloc(M) Rmalloc(M)
#define free(M) Rfree(M)
#define memory_get_count() Rmemory_get_count()
#endif

int server_domain = 0, server_cmd = TFTP_UNDEFINED;
char *server_ip = NULL, *server_port = NULL;

int server_s = -1;
int fd = -1; 				/* the file descriptor of the file being read/written. */

struct sockaddr_storage server_addr, recvfrom_addr;
socklen_t server_addrlen = 0, recvfrom_addrlen = 0;
bool have_transfer_address = false;

size_t pkt_hdr_sz = 4;
size_t pkt_data_sz = 512;

char *recv_buffer = NULL, *send_buffer = NULL, *recv_data = NULL;
ssize_t recv_sz, send_sz, recv_data_sz;

unsigned short recv_opcode = 0, recv_block = 0;
char *recv_filename = NULL, *recv_mode = NULL;

#ifdef DEBUG
void dump_pkt(char *pkt, int direction, ssize_t pkt_sz)
{
	int pkt_ptr = 0, pkt_hdr_len = 0, hdr_ptr = 0, h = 0;
	unsigned short opcode = 0, errcode = 0, blknum = 0;
	char *filename = NULL, *mode = NULL, *errmsg = NULL, *hdr_dump = NULL;
	
	log_msg(LOG_INFO, ">>> dump start - %s packet >>>", direction==XFRIN?"incoming":"outgoing");

	opcode = ntohs(*((unsigned short*)&pkt[pkt_ptr]));
	pkt_ptr += 2;
	if (opcode >= TFTP_OP_FIRST && opcode <= TFTP_OP_LAST)
	{
		switch(opcode)
		{
			case TFTP_OP_RRQ:
			case TFTP_OP_WRQ:
				filename = malloc(strlen(&pkt[pkt_ptr]) + 1);
				memset(filename, 0, strlen(&pkt[pkt_ptr]) + 1);
				memcpy(filename, &pkt[pkt_ptr], strlen(&pkt[pkt_ptr]));
				pkt_ptr += strlen(&pkt[pkt_ptr]) + 1;
				mode = malloc(strlen(&pkt[pkt_ptr]) + 1);
				memset(mode, 0, strlen(&pkt[pkt_ptr]) + 1);
				memcpy(mode, &pkt[pkt_ptr], strlen(&pkt[pkt_ptr]));
				pkt_ptr += strlen(&pkt[pkt_ptr]) + 1;
				
				log_msg(LOG_INFO, "opcode: %s, filename: %s, mode: %s, data_len: %u", tftp_opcode_name[opcode], filename, mode, pkt_sz - pkt_ptr);
				free(filename);
				free(mode);
				break;
			case TFTP_OP_DATA:
			case TFTP_OP_ACK:
				blknum = ntohs(*((unsigned short*)&pkt[pkt_ptr]));
				pkt_ptr += 2;
				
				log_msg(LOG_INFO, "opcode: %s, block#: %u, data_len: %u", tftp_opcode_name[opcode], blknum, pkt_sz - pkt_ptr);
				break;
			case TFTP_OP_ERROR:
				errcode = ntohs(*((unsigned short*)&pkt[pkt_ptr]));
				pkt_ptr += 2;
				if (errcode == TFTP_ERR_UNDEFINED && strlen(&pkt[pkt_ptr]))
				{
					errmsg = malloc(strlen(&pkt[pkt_ptr]) + 1);
					memset(errmsg, 0, strlen(&pkt[pkt_ptr]) + 1);
					memcpy(errmsg, &pkt[pkt_ptr], strlen(&pkt[pkt_ptr]));
				}
				pkt_ptr += strlen(&pkt[pkt_ptr]) + 1;
				
				log_msg(LOG_INFO, "opcode: %s, errorcode: %u, tftperr: %s, errmsg: %s, data_len: %u", tftp_opcode_name[opcode], errcode, tftp_error_string[errcode], errmsg==NULL?"none provided.":errmsg, pkt_sz - pkt_ptr);
				if (errmsg != NULL)
					free(errmsg);
				break;
			default:
				break;
		}
		pkt_hdr_len = pkt_ptr;
		
		hdr_dump = malloc((pkt_hdr_len * 5) + 1);
		memset(hdr_dump, 0, (pkt_hdr_len * 5) + 1);
		while(h < pkt_hdr_len)
		{
			hdr_ptr += sprintf(&hdr_dump[hdr_ptr], "%s", __hex(pkt[h]));
			h++;
		}
		log_msg(LOG_INFO, "%s", hdr_dump);
		free(hdr_dump);
	}
	else
		log_msg(LOG_INFO, "opcode: unknown");
		
	log_msg(LOG_INFO, "<<< dump end <<<");
}
#endif

void _log_msg(int priority, const char *msg, va_list args)
{
	char vbuf[2048], obuf[2048];
	int len = 0;
	
	vsnprintf(vbuf, 2048, msg, args);
	len = snprintf(obuf, 2048, "%s\n", vbuf);
	write(1, obuf, len);
}

void log_msg(int priority, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	_log_msg(priority, msg, args);
	va_end(args);
}

void exit_fail(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	_log_msg(LOG_ERR, msg, args);
	va_end(args);

	exit(EXIT_FAILURE);
}

void exit_handler(void)
{
	close_s(&server_s, "server_s");

	if (recv_buffer != NULL)
		free(recv_buffer);
	
	if (send_buffer != NULL)
		free(send_buffer);
	
	if (recv_filename != NULL)
		free(recv_filename);

	if (recv_mode != NULL)
		free(recv_mode);
	
#ifdef DEBUG
	log_msg(LOG_INFO, "end mem_count: %i", memory_get_count());
#endif
}

void close_s(int *s, char *name)
{
#ifdef DEBUG
	log_msg(LOG_INFO, "closing: %i (%s)", *s, name);
#endif

	if (*s != -1)
	{
		if (close(*s) == -1)
			fprintf(stderr, "failed to close %s\n", name);
		else
			*s = -1;
	}	
}

void signal_handler(int signal)
{
	switch (signal)
	{
		case SIGINT:
		case SIGTERM:
			exit(EXIT_SUCCESS);
			break;
	}
}

void usage(void)
{
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\ttftp <server ip> [ <server port> ] <command> <filename>\n\n");
	fprintf(stderr, "<server ip>   : The IP address of the server hosting the tftp daemon.\n");
	fprintf(stderr, "<server port> : The port the server is running on. Default: %s. OPTIONAL.\n", server_port_default);
	fprintf(stderr, "<command>     : GET | PUT (case insensitive)\n");
	fprintf(stderr, "<filename>    : The file to put to or get from the tftp daemon.\n");
}

void unpack_pkt(void)
{
	int ptr = 0;

	recv_opcode = ntohs(*((unsigned short*)&recv_buffer[0]));
	switch (recv_opcode)
	{
		/* a TFTP client should never receive these two messages.  this code is here because most of this codebase was copied from the server */
		case TFTP_OP_RRQ:
		case TFTP_OP_WRQ:
			ptr = 2;
			if (recv_filename != NULL)
			{
				free(recv_filename);
#ifdef DEBUG
				log_msg(LOG_INFO, "recv_filename != NULL");
#endif
			}
			if ((recv_filename = malloc(strlen(&recv_buffer[ptr]) + 1)) == NULL)
				exit_fail("failed to allocate memory for recv_filename");
			memset(recv_filename, 0, strlen(&recv_buffer[ptr]) + 1);
			strcpy(recv_filename, basename(&recv_buffer[ptr]));
			
			ptr = ptr + strlen(&recv_buffer[ptr]) + 1;
			if (recv_mode != NULL)
			{
				free(recv_mode);
#ifdef DEBUG
				log_msg(LOG_INFO, "recv_mode != NULL");
#endif
			}
			if ((recv_mode = malloc(strlen(&recv_buffer[ptr]) + 1)) == NULL)
				exit_fail("failed to allocate memory for recv_mode");
			memset(recv_mode, 0, strlen(&recv_buffer[ptr]) + 1);
			strcpy(recv_mode, &recv_buffer[ptr]);

			break;
		case TFTP_OP_DATA:
			recv_data = &recv_buffer[4];
			recv_data_sz = recv_sz - 4;
		case TFTP_OP_ACK:
			recv_block = ntohs(*((unsigned short*)&recv_buffer[2]));
			break;
		case TFTP_OP_ERROR:
			recv_errorcode = ntohs(*((unsigned short*)&recv_buffer[2]));
			if (recv_errmsg != NULL)
			{
				free(recv_errmsg);
#ifdef DEBUG
				log_msg(LOG_INFO, "recv_errmsg != NULL");
#endif		
			}
			if ((recv_errmsg = malloc(strlen(&recv_buffer[4]) + 1)) == NULL)
				exit_fail("failed to allocate memory for recv_mode");
			memset(recv_errmsg, 0, strlen(&recv_buffer[4]) + 1);
			strcpy(recv_errmsg, &recv_buffer[4]);
			break;
		default:
			exit_fail("Unknown opcode : OP = %u\n", recv_opcode);
	}
}

int send_pkt(void)
{
	if (sendto(server_s, send_buffer, send_sz, 0, (struct sockaddr*)&server_addr, server_addrlen) == -1)
		exit_fail("sendto() failed");

	return 1;
}

int recv_pkt(void)
{
	struct pollfd recv_fd;
	int res = 0, retries = 2;
	size_t addrlen = 0;
	void *c_addr = NULL, *r_addr = NULL;
	unsigned short *c_port = NULL, *r_port = NULL;

	/* obtain pointers to the server address/port and remote address/port for comparison */
	/* these could probably be initialised connection(), the addresses of the structures isn't going to change during execution. */
	switch (server_addr.ss_family)
	{
		case AF_INET:
			addrlen = 4;
			c_addr = &((struct sockaddr_in*)&server_addr)->sin_addr;
			c_port = &((struct sockaddr_in*)&server_addr)->sin_port;
			r_addr = &((struct sockaddr_in*)&recvfrom_addr)->sin_addr;
			r_port = &((struct sockaddr_in*)&recvfrom_addr)->sin_port;
			break;
		case AF_INET6:
			addrlen = 16;
			c_addr = &((struct sockaddr_in6*)&server_addr)->sin6_addr;
			c_port = &((struct sockaddr_in6*)&server_addr)->sin6_port;
			r_addr = &((struct sockaddr_in6*)&recvfrom_addr)->sin6_addr;
			r_port = &((struct sockaddr_in6*)&recvfrom_addr)->sin6_port;
			break;
	}

	while (retries)
	{
		recv_fd.fd = server_s;
		recv_fd.events = POLLIN;
		
		if ((res = poll(&recv_fd, 1, TIMEOUT(5, 0))) > 0)
		{
			memset(recv_buffer, 0, BUFFER_SZ);
			memset(&recvfrom_addr, 0, sizeof(struct sockaddr_storage));

			recvfrom_addrlen = server_addrlen;

			if ((recv_sz = recvfrom(server_s, recv_buffer, BUFFER_SZ, 0, (struct sockaddr*)&recvfrom_addr, &recvfrom_addrlen)) == -1)
				exit_fail("recvfrom() failed");

			if (have_transfer_address)
			{
				/* verify the incoming address (in recvfrom_addr) is the expected address/port pair. */
				if (memcmp(c_addr, r_addr, addrlen) || memcmp(c_port, r_port, sizeof(unsigned short)))
				{
					log_msg(LOG_INFO, "discarding packet from incorrect source");
					retries--;
					continue;
				}			
			}
			else
			{
				memcpy(&server_addr, &recvfrom_addr, recvfrom_addrlen);
				server_addrlen = recvfrom_addrlen;
				have_transfer_address = true;
			}
		}
		else
		{
			if (res == 0)
				return 0;
			else
				exit_fail("recv_pkt() poll() failed");
		}
		return 1;
	}
	
	return 0;
}



/*
CLIENT
RRQ sento

PrevBlk# Eq 0
	DATA recvfrom loop
		recvfrom DATA timeout DATA_BLOCK Eq Blk#
		If TimeOut
			Continue
		Else If DATA_Blk# NEq (PrevBlk# Plus 1)
			Continue
		WriteData To Disc
		sendto ACK ACK_BLOCK Eq DATA_Blk#
		If recvfrom_sz LessThan 512
			Break
		PrevBlk# Eq DATA_Blk#
*/
/* This is essentially the WRQ function from the Server */
void RRQ(void)
{
	unsigned int prev_blk = 0;
	int res = 0, retries = 2;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; /* equivalent to 0644 */

#ifdef DEBUG
	fprintf(stdout, "recv_filename = %s\n", recv_filename);	
#endif
	if ((fd = open(recv_filename, O_WRONLY | O_CREAT, mode)) == -1)
		exit_fail("failed to open %s for RRQ", recv_filename);
	
	log_msg(LOG_INFO, "reading %s from %s%s%s:%s", recv_filename, server_domain==AF_INET?"":"[", server_ip, server_domain==AF_INET?"":"]", server_port);
	
	memset(send_buffer, 0, BUFFER_SZ);
	*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_RRQ);
	send_sz = 2;
	send_sz += (sprintf(&send_buffer[send_sz], "%s", recv_filename) + 1);
	send_sz += (sprintf(&send_buffer[send_sz], "octet") + 1);

#ifdef DEBUG
	dump_pkt(send_buffer, XFROUT, send_sz);
#endif
	send_pkt();

	retries = 2;
	while (retries)
	{
		res = recv_pkt();

		if (res == 0)
		{
			retries--;
			continue;
		}
#ifdef DEBUG
		dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif
		unpack_pkt();
				
		if (recv_opcode == TFTP_OP_ERROR)
		{
			if (recv_errorcode > 0)
				exit_fail("transfer failed: %s", tftp_error_string[recv_errorcode]);
			else
				exit_fail("transfer failed: %s", recv_errmsg);
		}
		
		if (recv_block != (prev_blk + 1))
		{
			retries--;
			continue;
		}
		
		memset(send_buffer, 0, BUFFER_SZ);
		*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_ACK);
		*((unsigned int*)&send_buffer[2]) = htons(recv_block);
		send_sz = 4;
#ifdef DEBUG
		dump_pkt(send_buffer, XFROUT, send_sz);
#endif
		send_pkt();
		
		if (write(fd, recv_data, recv_data_sz) == -1)
			exit_fail("write() failed");
		
		if (recv_data_sz < pkt_data_sz)
			break;
		
		retries = 2;
		prev_blk = recv_block;
	}
	if (!retries)
		exit_fail("transfer timed-out");
	close_s(&fd, "fd");
}

/*
CLIENT
WRQ sentto
recvfrom ACK timeout

Blk# Eq 1
	DATA sendto Loop
		ReadData From Disc
		ACK recvfrom Loop
			sendto DATA DATA_BLOCK Eq Blk#
			recvfrom ACK timeout
			If TimeOut
				Continue
			Else If ACK_Blk# NEq DATA_Blk#
				Continue
			Else
				Break
		If sendto_sz LessThan 512
			Break
		Blk# Eq (Blk# Plus 1)
*/
/* This is essentially the RRQ function from the Server */
void WRQ(void)
{
	int blk = 1, retries = 0, res = 0;
	ssize_t read_sz = 0;

#ifdef DEBUG
	fprintf(stdout, "recv_filename = %s\n", recv_filename);
#endif
	if ((fd = open(recv_filename, O_RDONLY)) == -1)
		exit_fail("failed to open %s for WRQ", recv_filename);
	
	log_msg(LOG_INFO, "writing %s to %s%s%s:%s", recv_filename, server_domain==AF_INET?"":"[", server_ip, server_domain==AF_INET?"":"]", server_port);
	
	memset(send_buffer, 0, BUFFER_SZ);
	*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_WRQ);
	send_sz = 2;
	send_sz += (sprintf(&send_buffer[send_sz], "%s", recv_filename) + 1);
	send_sz += (sprintf(&send_buffer[send_sz], "octet") + 1);

#ifdef DEBUG
	dump_pkt(send_buffer, XFROUT, send_sz);
#endif
	send_pkt();

	retries = 2;
	while (retries)
	{
		res = recv_pkt();

		if (res == 0)
		{
			retries--;
			continue;
		}

#ifdef DEBUG
		dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif
		unpack_pkt();
		
		if (recv_opcode == TFTP_OP_ERROR)
		{
			if (recv_errorcode > 0)
				exit_fail("transfer failed: %s", tftp_error_string[recv_errorcode]);
			else
				exit_fail("transfer failed: %s", recv_errmsg);			
		}

		if (recv_opcode == TFTP_OP_ACK)
			break;

		retries--;
		fprintf(stderr, "dropping packet\n");
	}
	if (!retries)
		exit_fail("ACK failed to receive");	
	
	retries = 2;
	while (1)
	{
		memset(send_buffer, 0, BUFFER_SZ);
		*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_DATA);
		*((unsigned int*)&send_buffer[2]) = htons(blk);		

		if ((read_sz = read(fd, &send_buffer[4], pkt_data_sz)) == -1)
			exit_fail("read() failed");
		
		send_sz = 4 + read_sz;
		
		while(retries)
		{
#ifdef DEBUG
			dump_pkt(send_buffer, XFROUT, send_sz);
#endif	
			send_pkt();

			res = recv_pkt();
#ifdef DEBUG
			dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif
			if (res == 0)
			{
				retries--;
				continue;
			}
			
			unpack_pkt();
			
			if (recv_opcode == TFTP_OP_ERROR)
			{
				if (recv_errorcode > 0)
					exit_fail("transfer failed: %s", tftp_error_string[recv_errorcode]);
				else
					exit_fail("transfer failed: %s", recv_errmsg);
			}
			
			if (recv_block != blk)
			{
				retries--;
				continue;
			}
			break;
		}
		
		if (!retries)
			exit_fail("transfer timed-out");
		
		if (read_sz < pkt_data_sz)
			break;
		
		retries = 2;
		blk++;
	}
	close_s(&fd, "fd");
}

void transfer_core(void)
{
	struct addrinfo hints, *res = NULL;
	int gai_err = 0;
	struct timespec tic, toc;	
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = server_domain;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	
	if ((gai_err = getaddrinfo(server_ip, server_port, &hints, &res)))
		exit_fail("getaddrinfo() failed: %s", gai_strerror(gai_err));
	if ((server_s = socket(server_domain, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		exit_fail("failed to create udp socket");

	memset(&server_addr, 0, sizeof(struct sockaddr_storage));
	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addrlen = res->ai_addrlen;

	freeaddrinfo(res);
	
	recv_buffer = malloc(BUFFER_SZ);
	send_buffer = malloc(BUFFER_SZ);
	
	clock_gettime(CLOCK_MONOTONIC, &tic);	
	
	switch (server_cmd)
	{
		case TFTP_RRQ:
			RRQ();
			break;
		case TFTP_WRQ:
			WRQ();
			break;
	}
	
	clock_gettime(CLOCK_MONOTONIC, &toc);	
	log_msg(LOG_INFO, "elapsed time: %.2f seconds", (double)(toc.tv_sec - tic.tv_sec) + ((double)(toc.tv_nsec - tic.tv_nsec)/(double)1000000000));
}

int main(int argc, char *argv[], char *envp[])
{
	long port_t = 0;
	int opt = 1, stage = 0;
	
#ifdef DEBUG
	log_msg(LOG_INFO, "start mem_count: %i", memory_get_count());
#endif
	
	atexit(exit_handler);
	signal(SIGINT, signal_handler);	
	signal(SIGTERM, signal_handler);

	while (opt < argc && stage < 4)
	{
		switch (stage)
		{
			case 0:
				server_domain = parse_ip(argv[opt]);
				switch(server_domain)
				{
					case AF_INET:
					case AF_INET6:
						server_ip = argv[opt];
						break;
					default:
						exit_fail("failed to parse ip address");
						break;
				}
				break;
			case 1:
				if (parse_long(argv[opt], &port_t))
				{
					if (port_t < 1 || port_t > 65535)
						exit_fail("port value out of range: %li", port_t);
					server_port = argv[opt];
					break;
				}
				stage++;
			case 2:
				if (!strcasecmp(argv[opt], "get"))
					server_cmd = TFTP_RRQ;
				if (!strcasecmp(argv[opt], "put"))
					server_cmd = TFTP_WRQ;
				if (!server_cmd)
					exit_fail("invalid command: %s", argv[opt]);
				break;
			case 3:
				if ((recv_filename = malloc(strlen(argv[opt]) + 1)) == NULL)
					exit_fail("failed to allocate memory for the filename: %s", strerror);
				memset(recv_filename, 0, strlen(argv[opt]) + 1);
				memcpy(recv_filename, basename(argv[opt]), strlen(argv[opt]));
				break;
		}
		opt++;
		stage++;
	}

	if (server_ip == NULL)
		exit_fail("must supply an ip4 address to connect to");
	
	if (server_port == NULL)
		server_port = server_port_default;
	
	if (!server_cmd)
		exit_fail("must supply a command: GET | PUT");
	
	if (recv_filename == NULL)
		exit_fail("must supply a file name to send or receive");

#ifdef DEBUG
	fprintf(stdout, "server_ip     : %s\n", server_ip);
	fprintf(stdout, "server_domain : %s\n", server_domain==AF_INET?"AF_INET":"AF_INET6");
	fprintf(stdout, "server_port   : %s\n", server_port);
	fprintf(stdout, "server_cmd    : %s\n", tftp_opcode_name[server_cmd]);
	fprintf(stdout, "recv_filename : %s\n", recv_filename);
#endif
	
	transfer_core();

	exit(EXIT_SUCCESS);
}
