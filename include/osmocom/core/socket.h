/*! \file socket.h
 *  Osmocom socket convenience functions. */

#pragma once

/*! \defgroup socket Socket convenience functions
 *  @{
 *  \file socket.h */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if (!EMBEDDED)
#include <arpa/inet.h>

/*! maximum length of a socket name ("r=1.2.3.4:123<->l=5.6.7.8:987") */
#define OSMO_SOCK_NAME_MAXLEN (2 + INET6_ADDRSTRLEN + 1 + 5 + 3 + 2 + INET6_ADDRSTRLEN + 1 + 5 + 1)
#endif

struct sockaddr_in;
struct sockaddr;
struct osmo_fd;

/* flags for osmo_sock_init. */
/*! connect the socket to a remote peer */
#define OSMO_SOCK_F_CONNECT	(1 << 0)
/*! bind the socket to a local address/port */
#define OSMO_SOCK_F_BIND	(1 << 1)
/*! switch socket to non-blocking mode */
#define OSMO_SOCK_F_NONBLOCK	(1 << 2)
/*! disable multiast loop (IP_MULTICAST_LOOP) */
#define OSMO_SOCK_F_NO_MCAST_LOOP (1 << 3)
/*! disable receiving all multiast even for non-subscribed groups */
#define OSMO_SOCK_F_NO_MCAST_ALL  (1 << 4)
/*! use SO_REUSEADDR on UDP ports (required for multicast) */
#define OSMO_SOCK_F_UDP_REUSEADDR (1 << 5)

int osmo_sock_init(uint16_t family, uint16_t type, uint8_t proto,
		   const char *host, uint16_t port, unsigned int flags);

int osmo_sock_init2(uint16_t family, uint16_t type, uint8_t proto,
		   const char *local_host, uint16_t local_port,
		   const char *remote_host, uint16_t remote_port, unsigned int flags);

int osmo_sock_init_ofd(struct osmo_fd *ofd, int family, int type, int proto,
			const char *host, uint16_t port, unsigned int flags);

int osmo_sock_init2_ofd(struct osmo_fd *ofd, int family, int type, int proto,
			const char *local_host, uint16_t local_port,
			const char *remote_host, uint16_t remote_port, unsigned int flags);

int osmo_sock_init_sa(struct sockaddr *ss, uint16_t type,
		      uint8_t proto, unsigned int flags);

int osmo_sockaddr_is_local(struct sockaddr *addr, unsigned int addrlen);

unsigned int osmo_sockaddr_to_str_and_uint(char *addr, unsigned int addr_len, uint16_t *port,
					   const struct sockaddr *sa);
size_t osmo_sockaddr_in_to_str_and_uint(char *addr, unsigned int addr_len, uint16_t *port,
					const struct sockaddr_in *sin);

int osmo_sock_unix_init(uint16_t type, uint8_t proto,
			const char *socket_path, unsigned int flags);

int osmo_sock_unix_init_ofd(struct osmo_fd *ofd, uint16_t type, uint8_t proto,
			    const char *socket_path, unsigned int flags);

char *osmo_sock_get_name(void *ctx, int fd);
const char *osmo_sock_get_name2(int fd);
int osmo_sock_get_name_buf(char *str, size_t str_len, int fd);
int osmo_sock_get_ip_and_port(int fd, char *ip, size_t ip_len, char *port, size_t port_len, bool local);
int osmo_sock_get_local_ip(int fd, char *host, size_t len);
int osmo_sock_get_local_ip_port(int fd, char *port, size_t len);
int osmo_sock_get_remote_ip(int fd, char *host, size_t len);
int osmo_sock_get_remote_ip_port(int fd, char *port, size_t len);


int osmo_sock_mcast_loop_set(int fd, bool enable);
int osmo_sock_mcast_ttl_set(int fd, uint8_t ttl);
int osmo_sock_mcast_all_set(int fd, bool enable);
int osmo_sock_mcast_subscribe(int fd, const char *grp_addr);

int osmo_sock_local_ip(char *local_ip, const char *remote_ip);

/*! @} */
