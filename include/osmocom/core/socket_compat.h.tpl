#define __LIBOSMOCORE_HAVE_SYS_SOCKET_H XX
#define __LIBOSMOCORE_HAVE_NETINET_IN_H XX

#if __LIBOSMOCORE_HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
#else
/* Minimal netinet/in.h as per POSIX https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_socket.h.html */
#include <stdint.h>
typedef uint32_t socklen_t;
typedef unsigned short	sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct sockaddr_storage {
	sa_family_t ss_family;
	char __data[128 - sizeof(sa_family_t)];
};
#endif /* if __LIBOSMOCORE_HAVE_SYS_SOCKET_H */

#if __LIBOSMOCORE_HAVE_NETINET_IN_H
	#include <netinet/in.h>
#else
/* Minimal netinet/in.h as per POSIX https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/netinet_in.h.html */
#include <stdint.h>

typedef uint32_t in_addr_t;
struct in_addr {
	in_addr_t s_addr;
};

typedef uint16_t in_port_t;

struct in6_addr {
	union {
		uint8_t	__u6_addr8[16];
		uint16_t __u6_addr16[8];
		uint32_t __u6_addr32[4];
	} __in6_u;
	#define s6_addr		__in6_u.__u6_addr8
	#define s6_addr16	__in6_u.__u6_addr16
	#define s6_addr32	__in6_u.__u6_addr32
};

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

struct sockaddr_in {
	sa_family_t sin_family;
	in_port_t sin_port;
	struct in_addr sin_addr;
	unsigned char sin_zero[sizeof (struct sockaddr)
				- sizeof (sa_family_t)
				- sizeof (in_port_t)
				- sizeof (struct in_addr)];
};

struct sockaddr_in6 {
	sa_family_t sin6_family;
	in_port_t sin6_port;
	uint32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
	uint32_t sin6_scope_id;
};

#endif /* if __LIBOSMOCORE_HAVE_NETINET_IN_H */
