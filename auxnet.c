#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if (PARSE_IP_TO_ADDR)
int parse_ip(char *str, void *addr)
{
	if (inet_pton(AF_INET, str, addr) == 1)
	{
		return AF_INET;
	}
	
	if (inet_pton(AF_INET6, str, addr) == 1)
	{
		return AF_INET6;
	}
	
	return 0;
}
#else
int parse_ip(char *str)
#endif
{
	char addr[16];

	if (inet_pton(AF_INET, str, addr) == 1)
		return AF_INET;
	
	if (inet_pton(AF_INET6, str, addr) == 1)
		return AF_INET6;
	
	return 0;
}

/*
A wrapper around inet_ntop that accommodates both IPv4 and IPv6.
It is excpected that name points to a valid buffer space and size
is how big the buffer is.
*/
char *addr_str(struct sockaddr* addr, char *name, socklen_t size)
{
	int socknamelen = 0;
	int sockfamily = 0;
	void *sockaddr = NULL;
	
	sockfamily = addr->sa_family;
	switch (addr->sa_family)
	{	
		case AF_INET:
			sockaddr = &((struct sockaddr_in*)addr)->sin_addr;
			socknamelen = INET_ADDRSTRLEN>size?size:INET_ADDRSTRLEN;
			break;
		case AF_INET6:
			sockaddr = &((struct sockaddr_in6*)addr)->sin6_addr;
			socknamelen = INET6_ADDRSTRLEN>size?size:INET6_ADDRSTRLEN;
		break;
	}
	
	if (inet_ntop(sockfamily, (struct sockaddr*)sockaddr, name, socknamelen) == NULL)
		return NULL;
	
	return name;
}
