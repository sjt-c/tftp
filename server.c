/*

tftpd - trivial file transfer server

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

#include <ifaddrs.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#include <libgen.h>

#include "tftp.h"
#include "auxnet.h"
#include "auxmath.h"

#ifdef DEBUG
#include "iso_iec_646.h"
#endif

#define XFRIN			0
#define XFROUT			1

#define IDENT_SERVER	0
#define IDENT_WORKER	1

/* the default values for these are defined below. */
#define BUFFER_SZ 		(pkt_hdr_sz + pkt_data_sz)

/* recycle the variables for use with an error packet. */
#define recv_errorcode	recv_block
#define recv_errmsg		recv_mode

char *ident_strings[] = { "server", "worker" };
char *ident = NULL;

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
void send_error_pkt(int errorcode, const char *msg, ...);
void RRQ(void);
void WRQ(void);
void connection(int incoming_sock);
void listen_core(void);

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

/* boolean flags */
int daemonize_enable = 0, ipv4_enable = 1, ipv6_enable = 1, log_to_syslog = 1;
char *root = NULL;					/* the directory chroot changes into when daemonizing */

char *listen_port = NULL;			/* port the server listens on.  default value is in tftp.h, can be changed via command line options */
struct pollfd *server_fds = NULL;
int n_fds = 0;						/* total number of file descriptors opened in listen core */
int server_s = -1;					/* the worker socket (should be renamed to worker_s */
int fd = -1;						/* the file descriptor for the file being read/written. */

struct sockaddr_storage client_addr, recvfrom_addr;	/* address of the client and address each received packet comes from */
socklen_t client_addrlen = 0, recvfrom_addrlen = 0;

/* the default values for a tftp packet. */
size_t pkt_hdr_sz = 4;		/* size (bytes) of a packet header */
size_t pkt_data_sz = 512;	/* size (bytes) of a packet maximum data payload */

char *recv_buffer = NULL;	/* buffer for recv_pkt */
char *send_buffer = NULL;	/* buffer for send_pkt. */
ssize_t recv_sz, send_sz;	/* the amount of data received by recv_pkt, or to send for send_pkt. */

/* filled out by unpack_pkt() */
char *recv_data = NULL;		/* a pointer to the start of the data block in recv_buffer. */
ssize_t recv_data_sz;		/* the size of the recv_data block. */
unsigned short recv_opcode = 0, recv_block = 0;	/* check the define above, recv_errorcode is an alias for recv_block */
char *recv_filename = NULL, *recv_mode = NULL;	/* check the define above, recv_errmsg is an alias for recv_mode */

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
	
	if (log_to_syslog)
	{
		openlog("tftpd", LOG_PID, LOG_FTP);
		vsyslog(priority, msg, args);
		closelog();
	}
	else
	{
		vsnprintf(vbuf, 2048, msg, args);
		len = snprintf(obuf, 2048, "%s\n", vbuf);
		write(1, obuf, len);
	}
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
	int c_fd = 0;
	char sockname[18];
	
	if (server_fds != NULL)
	{
		for (c_fd = 0; c_fd < n_fds ; c_fd++)
		{
			snprintf(sockname, 18, "server_fds[%i].fd", c_fd);
			close_s(&server_fds[c_fd].fd, sockname);
		}
		free(server_fds);
	}
	
	close_s(&server_s, "server_s");
	
	close_s(&fd, "fd");
	
	if (recv_buffer != NULL)
		free(recv_buffer);
	
	if (send_buffer != NULL)
		free(send_buffer);
	
	if (recv_filename != NULL)
		free(recv_filename);
	
	if (recv_mode != NULL)
		free(recv_mode);
	
#ifndef DEBUG	
	log_msg(LOG_INFO, "%s ending.", ident);
#else
	log_msg(LOG_INFO, "%s ending. mem_count: %i", ident, memory_get_count());
#endif
}

/* a wrapper around close(2) to ensure it isn't called on an already closed file descriptor */
void close_s(int *s, char *name)
{
#ifdef DEBUG
	log_msg(LOG_INFO, "closing: %i (%s)", *s, name);
#endif
	if (*s != -1)
	{
		if (close(*s) == -1)
			log_msg(LOG_ERR, "failed to close %s\n", name);
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
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, "\ttftpd [-p <port> ] [-D -C <root>] [-T] [-4|-6]\n\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, "\t-D : daemonize the server, -C must be specified as well.\n");
	fprintf(stdout, "\t-T : logging to stdout. (see Notes)\n");
	fprintf(stdout, "\t-C : the directory to chroot into.\n");
	fprintf(stdout, "\t-p : port to listen on.  default is %s.\n", SERVER_PORT);
	fprintf(stdout, "\t-4 : bind to ipv4 addresses only.\n");
	fprintf(stdout, "\t-6 : bind to ipv6 addresses only.\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Notes:\n");
	fprintf(stdout, "\to to shutdown the server send it SIGINT or SIGTERM.\n");
	fprintf(stdout, "\to if -T is specified, -D -C are ignored and the server stays in the\n\tforeground.  all logging is directed to stdout.\n");
	fprintf(stdout, "\n\n");
}

void unpack_pkt(void)
{
	int ptr = 0;
	
	recv_opcode = ntohs(*((unsigned short*)&recv_buffer[0]));
	switch (recv_opcode)
	{
		case TFTP_OP_RRQ:
		case TFTP_OP_WRQ:
			ptr = 2;
			/* veryify filename length (check tftp.h) */
			if (strlen(&recv_buffer[ptr]) > TFTP_FILENAME_LEN)
			{
				send_error_pkt(TFTP_ERR_UNDEFINED, "Filename too long.");
				exit_fail("filename too long");
			}
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
			/* verify mode length */
			if (strlen(&recv_buffer[ptr]) > TFTP_MODE_LEN)
			{
				send_error_pkt(TFTP_ERR_UNDEFINED, "Mode too long.");
				exit_fail("mode too long");
			}
			/* verify mode is one of "octet", "netascii", or "mail". */
			if (strncasecmp(&recv_buffer[ptr], "octet", TFTP_MODE_OCTET) && strncasecmp(&recv_buffer[ptr], "netascii", TFTP_MODE_NETASCII) && strncasecmp(&recv_buffer[ptr], "mail", TFTP_MODE_MAIL))
			{
				send_error_pkt(TFTP_ERR_UNDEFINED, "Mode \"%s\" unknown.", &recv_buffer[ptr]);
				exit_fail("mode too long");				
			}
			/* verify mode is supported. */
			if (strncasecmp(&recv_buffer[ptr], "octet", TFTP_MODE_OCTET))
			{
				send_error_pkt(TFTP_ERR_UNDEFINED, "Mode \"%s\" unsupported.", &recv_buffer[ptr]);
				exit_fail("mode unsupported");				
			}
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
	if (sendto(server_s, send_buffer, send_sz, 0, (struct sockaddr*)&client_addr, client_addrlen) == -1)
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

	/* pointers to the client address/port and incoming packet remote/port */
	/* these could probably be initialised connection(), the addresses of the structures isn't going to change during execution. */
	switch (client_addr.ss_family)
	{
		case AF_INET:
			addrlen = 4;
			c_addr = &((struct sockaddr_in*)&client_addr)->sin_addr;
			c_port = &((struct sockaddr_in*)&client_addr)->sin_port;
			r_addr = &((struct sockaddr_in*)&recvfrom_addr)->sin_addr;
			r_port = &((struct sockaddr_in*)&recvfrom_addr)->sin_port;
			break;
		case AF_INET6:
			addrlen = 16;
			c_addr = &((struct sockaddr_in6*)&client_addr)->sin6_addr;
			c_port = &((struct sockaddr_in6*)&client_addr)->sin6_port;
			r_addr = &((struct sockaddr_in6*)&recvfrom_addr)->sin6_addr;
			r_port = &((struct sockaddr_in6*)&recvfrom_addr)->sin6_port;
			break;
	}

	/* this outer while loop is to accommodate packets coming from incorrect source address/port */
	while (retries)
	{
		/* (re)set the poll structure */
		recv_fd.fd = server_s;
		recv_fd.events = POLLIN;
		recv_fd.revents = 0;
		
		/* poll with a time-out */
		if ((res = poll(&recv_fd, 1, TIMEOUT(5, 0))) > 0)
		{
			/* reset the receive buffer and incoming packet address */
			memset(recv_buffer, 0, BUFFER_SZ);
			memset(&recvfrom_addr, 0, sizeof(struct sockaddr_storage));
			recvfrom_addrlen = client_addrlen;
			
			/* attempt to receive a packet */
			if ((recv_sz = recvfrom(server_s, recv_buffer, BUFFER_SZ, 0, (struct sockaddr*)&recvfrom_addr, &recvfrom_addrlen)) == -1)
				exit_fail("recvfrom() failed");
			
			/* verify the incoming packet address (in recvfrom_addr) is the expected address/port pair. */
			if (memcmp(c_addr, r_addr, addrlen) || memcmp(c_port, r_port, sizeof(unsigned short)))
			{
				log_msg(LOG_INFO, "discarding packet from incorrect source");
				retries--;
				continue;
			}
		}
		else
		{
			/* poll() failed... */
			if (res == 0)
				/* timeout */
				return 0;
			else
				/* exit on all other errors */
				exit_fail("recv_pkt() poll() failed");
		}
		
		/* will reach this point on a successful packet arrival. */
		return 1;
	}
	
	/* will reach this point if enough incorrect packets have arrived and retries reaches 0. */
	return 0;
}

void send_error_pkt(int errorcode, const char *msg, ...)
{
	va_list args;
	char va_buf[2048];
	
	va_start(args, msg);
	vsnprintf(va_buf, 2048, msg, args);
	va_end(args);
	
	memset(send_buffer, 0, BUFFER_SZ);
	*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_ERROR);
	*((unsigned int*)&send_buffer[2]) = htons(errorcode);
	send_sz = 4;
	if (strlen(va_buf))
	{
		strcpy(&send_buffer[4], va_buf);
		send_sz += (strlen(va_buf) + 1);
	}
#ifdef DEBUG
	dump_pkt(send_buffer, XFROUT, send_sz);
#endif	
	send_pkt();
}

void RRQ(void)
{
	int /* fd = -1, */ blk = 1, retries = 0, res = 0;
	ssize_t read_sz = 0;

#ifdef DEBUG
	log_msg(LOG_INFO, "recv_filename = %s", recv_filename);
#endif
	/* attempt to open for reading the requested file. */
	if ((fd = open(recv_filename, O_RDONLY)) == -1)
	{
		send_error_pkt(TFTP_ERR_FILE_NOT_FOUND, recv_filename);
		exit_fail("failed to open %s for RRQ", recv_filename);
	}
	
	log_msg(LOG_INFO, "sending: %s", recv_filename);

	retries = 2;
	while (1)
	{
		/* prepare a TFTP_DATA packet. */
		memset(send_buffer, 0, BUFFER_SZ);
		*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_DATA);
		*((unsigned int*)&send_buffer[2]) = htons(blk);		

		if ((read_sz = read(fd, &send_buffer[4], pkt_data_sz)) == -1)
			exit_fail("read() failed");
		
		send_sz = 4 + read_sz;
		
		while (retries)
		{
#ifdef DEBUG
			dump_pkt(send_buffer, XFROUT, send_sz);
#endif	
			/* send the prepared TFTP_DATA packet. */
			send_pkt();
			
			/* wait on TFTP_ACK or TFTP_ERROR. */
			res = recv_pkt();

			/* on time-out or incorrect source packets continue waiting */
			if (res == 0)
			{
				retries--;
				continue;
			}
#ifdef DEBUG
			dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif	
			
			/* unpack the response into variables. */
			unpack_pkt();
			
			/* TFTP_ERROR received */
			if (recv_opcode == TFTP_OP_ERROR)
			{
				if (recv_errorcode > 0)
					exit_fail("transfer failed: %s", tftp_error_string[recv_errorcode]);
				else
					exit_fail("transfer failed: %s", recv_errmsg);
			}
			
			/* TFTP_ACK received with correct Block# */
			if (recv_opcode == TFTP_OP_ACK && recv_block == blk)
				break;
			
			/* will reach this point if:
			(a) TFTP_ACK with an incorrect Block#, OR
			(b) anything else received. */
			retries--;
			continue;
		}
		/* will reach this point if:
		(a) the DATA packet was sent and correct ACK received, OR 
		(b) retries is 0. */
		if (!retries)
			exit_fail("transfer timed-out");
		
		/* TFTP transfer ends when received data payload smaller than maximum allowed. */
		if (read_sz < pkt_data_sz)
			break;
		
		/* wait on next packet */
		retries = 2;
		blk++;
	}
	
	/* transfer completed successfully. */
	close_s(&fd, "fd");
}

void WRQ(void)
{
	unsigned int prev_blk = 0;
	int res = 0, retries = 2;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; /* equivalent to 0644 */

#ifdef DEBUG
	log_msg(LOG_INFO, "recv_filename = %s", recv_filename);
#endif
	/* attempt to open for writing the requested filename. */
	if ((fd = open(recv_filename, O_WRONLY | O_CREAT, mode)) == -1)
	{
		send_error_pkt(TFTP_ERR_ACCESS_VIOLATION, recv_filename);
		exit_fail("failed to open %s for WRQ", recv_filename);
	}
	
	log_msg(LOG_INFO, "receiving: %s", recv_filename);
	
	/* send initial TFTP_ACK to the client. */
	memset(send_buffer, 0, BUFFER_SZ);
	*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_ACK);
	send_sz = 4;
#ifdef DEBUG
	dump_pkt(send_buffer, XFROUT, send_sz);
#endif	
	send_pkt();
	
	retries = 2;
	while (retries)
	{
		/* wait on TFTP_DATA or TFTP_ERROR */
		res = recv_pkt();
		
		/* on time-out, continue waiting. */
		if (res == 0)
		{
			retries--;
			continue;
		}
		
#ifdef DEBUG
		dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif
		/* unpack the packet into meaningful variables. */
		unpack_pkt();
		
		/* TFTP_ERROR received. */
		if (recv_opcode == TFTP_OP_ERROR)
		{
			if (recv_errorcode > 0)
				exit_fail("transfer failed: %s", tftp_error_string[recv_errorcode]);
			else
				exit_fail("transfer failed: %s", recv_errmsg);
		}
		
		/* TFTP_DATA with correct Block# */
		if (recv_opcode == TFTP_OP_DATA && (recv_block == prev_blk + 1))
		{
			/* prepare and send TFTP_ACK. */
			memset(send_buffer, 0, BUFFER_SZ);
			*((unsigned int*)&send_buffer[0]) = htons(TFTP_OP_ACK);
			*((unsigned int*)&send_buffer[2]) = htons(recv_block);
			send_sz = 4;
#ifdef DEBUG
			dump_pkt(send_buffer, XFROUT, send_sz);
#endif	
			send_pkt();
			
			/* attempt to write data to file. */
			if (write(fd, recv_data, recv_data_sz) == -1)
				exit_fail("write() failed");
			
			/* a TFTP transfer ends when the data payload is less than the maximum allowed. */
			if (recv_data_sz < pkt_data_sz)
				break;
			
			/* wait on next packet. */
			retries = 2;
			prev_blk = recv_block;
		}
		else
		{
			/* will get to here if the packet was:
			(a) TFTP_DATA with an incorrect Block#, OR
			(b) anything else was received.*/
			retries--;
		}
	}
	
	/* will reach this point if:
	(a) the transfer completed successfully OR,
	(b) retries is 0. */
	if (!retries)
		exit_fail("transfer timed-out");

	/* transfer completed successfully. */
	close_s(&fd, "fd");
}

void connection(int incoming_sock)
{
	struct sockaddr_storage local_addr;
	socklen_t local_addrlen = 0;
	int c_fd = 0;
	char sockname[INET6_ADDRSTRLEN];
	int sockfamily = 0;
	void *sockaddr = NULL;
	struct addrinfo hints, *res0 = NULL;
	int gai_err = 0;
	struct timespec tic, toc;	

	ident = ident_strings[IDENT_WORKER];
#ifndef DEBUG
	log_msg(LOG_INFO, "%s started.", ident);
#else
	log_msg(LOG_INFO, "%s started. mem_count: %i", ident, memory_get_count());
#endif
	
	/* get the address of the socket the client connection came in on. */
	memset(&local_addr, 0, sizeof(struct sockaddr_storage));
	local_addrlen = sizeof(struct sockaddr_storage);

	if (getsockname(incoming_sock, (struct sockaddr*)&local_addr, &local_addrlen))
		exit_fail("getsockname(%i) failed: %s", incoming_sock, strerror(errno));
	
	/* close all listening sockets that were inherited from before the fork(), and clean up the memory */
	for (c_fd = 0; c_fd < n_fds ; c_fd++)
	{
		snprintf(sockname, INET6_ADDRSTRLEN, "server_fds[%i].fd", c_fd);
		close_s(&server_fds[c_fd].fd, "sockname");
	}
	free(server_fds);
	server_fds = NULL;
	
	log_msg(LOG_INFO, "local address: %s", addr_str((struct sockaddr*)&local_addr, sockname, INET6_ADDRSTRLEN));
	log_msg(LOG_INFO, "remote address: %s", addr_str((struct sockaddr*)&client_addr, sockname, INET6_ADDRSTRLEN));

	/* make a text representation of the address to pass to getaddrinfo(). */
	sockfamily = local_addr.ss_family;
	switch (sockfamily)
	{
		case AF_INET:
			sockaddr = &((struct sockaddr_in*)&local_addr)->sin_addr;
			break;
		case AF_INET6:
			sockaddr = &((struct sockaddr_in6*)&local_addr)->sin6_addr;
			break;
	}	
	if (inet_ntop(sockfamily, (struct sockaddr*)sockaddr, sockname, INET6_ADDRSTRLEN) == NULL)
		exit_fail("inet_ntop(%s, ...) failed: %s\n", local_addr.ss_family==AF_INET?"AF_INET":"AF_INET6", strerror(errno));
	
	/* make a new socket on the same address the connection came in on but with an ephemeral port number. */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = local_addr.ss_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	
	if ((gai_err = getaddrinfo(sockname, NULL, &hints, &res0)))
		exit_fail("getaddrinfo() failed: %s", gai_strerror(gai_err));
	
	if ((server_s = socket(local_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		exit_fail("failed to create udp socket");
	
	if (bind(server_s, res0->ai_addr, res0->ai_addrlen) == -1)
		exit_fail("failed to bind udp socket");
	
	/* what is this being used for??? */
/*	client_addrlen = res0->ai_addrlen; */
	
	freeaddrinfo(res0);
	
	/* unpack the received packet into meaningful variables. */
	unpack_pkt();

	clock_gettime(CLOCK_MONOTONIC, &tic);	

	/* if the packet doesn't have a valid tftp opcode this child will simply exit quietly, otherwise go off and handle
	the request. */
#ifdef DEBUG
	dump_pkt(recv_buffer, XFRIN, recv_sz);
#endif	
	switch (recv_opcode)
	{
		case TFTP_OP_RRQ:
			RRQ();
			break;
		case TFTP_OP_WRQ:
			WRQ();
			break;
	}
	
	clock_gettime(CLOCK_MONOTONIC, &toc);	
	log_msg(LOG_INFO, "elapsed time: %.2f seconds", (double)(toc.tv_sec - tic.tv_sec) + ((double)(toc.tv_nsec - tic.tv_nsec)/(double)1000000000));

	exit(EXIT_SUCCESS);
}

void listen_core(void)
{
	struct ifaddrs *addrs0 = NULL, *addrs = NULL;
	void *sockaddr = NULL;
	int sockfamily = 0;
	char sockname[INET6_ADDRSTRLEN];
	int c_fd = 0;
	struct addrinfo hints, *res0 = NULL;
	int gai_err = 0;
	int poll_ret = 0;
	pid_t child_pid;

	/* obtain a list of all interface address. */
	if (getifaddrs(&addrs0))
		exit_fail("getifaddrs() failed: %s", strerror(errno));

	/* count the number of addresses that are going to be needed, and ignore address family if it has been excluded. also ignore link-local ipv6
	addresses. */
	addrs = addrs0;
	while (addrs)
	{
		if (((addrs->ifa_addr->sa_family == AF_INET) & ipv4_enable) || ((addrs->ifa_addr->sa_family == AF_INET6) & ipv6_enable & !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6*)addrs->ifa_addr)->sin6_addr)))
			n_fds += 1;
		addrs = addrs->ifa_next;
	}
	
	/* allocate space for the poll structures for each socket and initialise the file descriptors to -1. */
#ifdef DEBUG
	if (server_fds != NULL)
		log_msg(LOG_INFO, "server_fds != NULL");
#endif
	if ((server_fds = malloc(n_fds * sizeof(struct pollfd))) == NULL)
		exit_fail("malloc(server_fds[%i]) failed: %s", n_fds, strerror(errno));
	memset(server_fds, 0, n_fds * sizeof(struct pollfd));
	
	for (c_fd = 0; c_fd < n_fds ; c_fd++)
		server_fds[c_fd].fd = -1;

	/* iterate again over the list of addresses, filtering excluded addresses and create a UDP socket for each address. the results go in server_fds[x].fd. */
	c_fd = 0;
	addrs = addrs0;
	while (addrs)
	{
		/* skip excluded addresses. */
		if (((addrs->ifa_addr->sa_family == AF_INET) & ipv4_enable) || ((addrs->ifa_addr->sa_family == AF_INET6) & ipv6_enable  & !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6*)addrs->ifa_addr)->sin6_addr)))
		{
			/* make a text representation of the address for use with getaddrinfo(). (and debugging) */
			sockfamily = addrs->ifa_addr->sa_family;
			switch (addrs->ifa_addr->sa_family)
			{	
				case AF_INET:
					sockaddr = &((struct sockaddr_in*)(addrs->ifa_addr))->sin_addr;
					break;
				case AF_INET6:
					sockaddr = &((struct sockaddr_in6*)(addrs->ifa_addr))->sin6_addr;
				break;
			}
			if (inet_ntop(sockfamily, sockaddr, sockname, INET6_ADDRSTRLEN) == NULL)
				exit_fail("inet_ntop(%i) failed: %s", c_fd, strerror(errno));
			
			/* create an addrinfo structure for the required address.  this could be done with individual elements using the pointer
			above to copy the correct address in. */
			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = sockfamily;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
			
			if ((gai_err = getaddrinfo(sockname, listen_port, &hints, &res0)))
				exit_fail("getaddrinfo() failed: %s", gai_strerror(gai_err));
		
			/* exit if getaddrinfo() didn't return an error, but also didn't return a result. pretty sure this test isn't necessary. */
			if (res0 == NULL)
				exit_fail("res0 == NULL");
		
			/* create a UDP socket with the appropriate family. */
			if ((server_fds[c_fd].fd = socket(res0->ai_family, res0->ai_socktype, res0->ai_protocol)) == -1)
				exit_fail("socket(%s) failed: %s", (res0->ai_family==AF_INET?"ipv4":"ipv6"), strerror(errno));
			
			/* bind the UDP socket to the appropriate address. */
			if (bind(server_fds[c_fd].fd, res0->ai_addr, res0->ai_addrlen))
				exit_fail("bind(%i, %s, ...) failed: %s", server_fds[c_fd].fd, sockname, strerror(errno));
#ifdef DEBUG
			log_msg(LOG_INFO, "%s UDP socket, %i, created: %s", (res0->ai_family==AF_INET?"IPv4":"IPv6"), server_fds[c_fd], sockname);
#endif
			/* clean up from getaddrinfo() */
			freeaddrinfo(res0);

			c_fd += 1;
		}
		addrs = addrs->ifa_next;
	}
	freeifaddrs(addrs0);

	/* allocate space for the two primary sending and receiving buffers. */
#ifdef DEBUG
	if (recv_buffer != NULL)
		log_msg(LOG_INFO, "recv_buffer != NULL");
#endif
	if ((recv_buffer = malloc(BUFFER_SZ)) == NULL)
		exit_fail("failed to allocate recv_buffer");
	
#ifdef DEBUG
	if (send_buffer != NULL)
		log_msg(LOG_INFO, "send_buffer != NULL");
#endif
	if ((send_buffer = malloc(BUFFER_SZ)) == NULL)
		exit_fail("failed to allocate send_buffer");
	
	/* infinite poll loop.  signal handling takes care of exit & shutdown. */
	while (1)
	{
		/* (re)initialise the events & revents fields of the poll structure. */
		for (c_fd = 0; c_fd < n_fds; c_fd++)
		{
			server_fds[c_fd].events = POLLIN;
			server_fds[c_fd].revents = 0;
		}
		
		/* poll the set of fd's for any that are ready for reading.  this could be set to a blocking poll. */
		if ((poll_ret = poll(server_fds, n_fds, TIMEOUT(5,0))) > 0)
		{
			/* make sure the receiving buffer is clear. */
			memset(recv_buffer, 0, BUFFER_SZ);
			
			/* clear the space for the client address. */
			memset(&client_addr, 0, sizeof(struct sockaddr_storage));
			client_addrlen = sizeof(struct sockaddr_storage);

			/* iterate over the poll structure looking for the fd that's ready to receive. */
			for (c_fd = 0; c_fd < n_fds ; c_fd++)
			{
				if (server_fds[c_fd].revents & POLLIN)
				{
					if ((recv_sz = recvfrom(server_fds[c_fd].fd, recv_buffer, BUFFER_SZ, 0, (struct sockaddr*)&client_addr, &client_addrlen)) == -1)
						exit_fail("recvfrom() failed");
			
					/* fork() a child process to handle the connection. */
					if ((child_pid = fork() == 0))
						connection(server_fds[c_fd].fd);
					if (child_pid == -1)
						exit_fail("failed to fork service process");
				}
			}
		}
		else
		{
			/* poll returned with ... */
			if (poll_ret == 0)
				/* a timeout, continue listening. */
				continue;
			else
				/* an error, report it and exit. */
				exit_fail("poll() failed");
		}		
	}
	/* SHOULD NEVER REACH THIS POINT. */
}

void daemonize(void)
{
	pid_t pid;
	int s;

	/* fork from the parent process. */
	pid = fork();

	/* the fork failed, exit the parent. */
	if (pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* the fork succeeded, exit the parent. */
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	/* create a new session id for the child. */
	if (setsid() < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* ignore these two signals while calling the next fork. */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* fork again. */
	pid = fork();

	/* the fork failed, exit the parent. */
	if (pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* the fork succeeded, exit the parent. */
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	/* clear the umask so it has to be specifically reset later. */
	umask(0);
	
	/* change into the desired root directory. */
	if (chdir(root))
	{
		log_msg(LOG_ERR, "chroot to %s failed.\n", root);
		exit(EXIT_FAILURE);
	}

	/* close all open file descriptors.  this should only be 0, 1, and 2. */
	for (s = sysconf(_SC_OPEN_MAX); s >= 0; s--)
	{
		close(s);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	long port_t = 0;
	int opt = 0;
	
	/* process all command line options. */
	while ((opt = getopt(argc, argv, "h46p:C:DT")) != -1)
	{
		switch (opt)
		{
			case '4':
				if (!ipv4_enable)
				{
					fprintf(stderr, "can only specify either ipv4 OR ipv6, not both.\n");
					exit(EXIT_FAILURE);
				}
				ipv6_enable = 0;
				break;
			case '6':
				if (!ipv6_enable)
				{
					fprintf(stderr, "can only specify either ipv4 OR ipv6, not both.\n");
					exit(EXIT_FAILURE);
				}
				ipv4_enable = 0;
				break;
			case 'p':
				if (!parse_long(optarg, &port_t))
				{
					fprintf(stderr, "failed to parse port: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				if (port_t < 1 || port_t > 65535)
				{
					fprintf(stderr, "port value out of range (1..65535): %li\n", port_t);
					exit(EXIT_FAILURE);
				}
				listen_port = optarg;
				break;
			case 'D':
				daemonize_enable = 1;
				break;
			case 'C':
				root = optarg;
				break;
			case 'T':
				log_to_syslog = 0;
				break;
			case 'h':
			case '?':
			default:
				usage();
				exit(EXIT_FAILURE);
				break;
		}
	}
	argc -= optind;
	argv += optind;
	
	/* check a chroot location has been specified with daemonize */
	if (root == NULL && daemonize_enable)
	{
		usage();
		fprintf(stderr, "must supply a path to the root directory.\n");
		exit(EXIT_FAILURE);
	}

	/* if no port has been specified use the value in tftp.h */
	if (listen_port == NULL)
		listen_port = server_port_default;

	/* if -T hasn't been specified and daemonize has, daemonize into the background. */
	if (daemonize_enable && log_to_syslog)
		daemonize();

	/* register the atexit handler. */
	atexit(exit_handler);
	
	/* register signal handlers. */
	signal(SIGINT, signal_handler);	
	signal(SIGTERM, signal_handler);
	
	ident = ident_strings[IDENT_SERVER];

#ifndef DEBUG	
	log_msg(LOG_INFO, "%s started.", ident);
#else
	log_msg(LOG_INFO, "%s started. mem_count: %i", ident, memory_get_count());
#endif
	
	/* start the process of listening for connections. */
	listen_core();

	/* SHOULD NEVER REACH THIS POINT. */
	exit(EXIT_SUCCESS);
}
