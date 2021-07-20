#ifndef __AUXNET_H__
#define __AUXNET_H__

#if (0)
#define PARSE_IP_TO_ADDR
#endif

#if (PARSE_IP_TO_ADDR)
int parse_ip(char *str, void *addr)
#else
int parse_ip(char *str);
#endif

char *addr_str(struct sockaddr* addr, char *name, socklen_t size);

#endif /* __AUXNET_H__ */
