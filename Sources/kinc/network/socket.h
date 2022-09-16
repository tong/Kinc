#pragma once

#include <kinc/global.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KORE_MICROSOFT
#if defined(_WIN64)
typedef unsigned __int64 UINT_PTR, *PUINT_PTR;
#else
#if !defined _W64
#define _W64
#endif
typedef _W64 unsigned int UINT_PTR, *PUINT_PTR;
#endif
typedef UINT_PTR SOCKET;
#endif

typedef enum kinc_socket_protocol { KINC_SOCKET_PROTOCOL_UDP, KINC_SOCKET_PROTOCOL_TCP } kinc_socket_protocol_t;

typedef struct kinc_socket {
#ifdef KORE_MICROSOFT
	SOCKET handle;
#else
	int handle;
#endif
} kinc_socket_t;

// KINC_FUNC int kinc_getaddrinfo(char *host, int port, struct addrinfo *hints, struct addrinfo *servinfo);
KINC_FUNC int kinc_get_hostname(char *hostname, int size);
KINC_FUNC int kinc_host_resolve(char *host);
KINC_FUNC char *kinc_host_to_string(int host);

KINC_FUNC int kinc_socket_connect(kinc_socket_t *sock, char *host, int port, int type, int family);

KINC_FUNC int kinc_socket_bind(kinc_socket_t *sock, char *host, int port, int type, int family);
KINC_FUNC bool kinc_socket_listen(kinc_socket_t *sock, unsigned int backlog);
KINC_FUNC bool kinc_socket_accept(kinc_socket_t *sock, kinc_socket_t *new_socket, uint32_t *remoteAddress, uint16_t *remotePort);
//KINC_FUNC bool kinc_socket_select(read, write, others, timeout);

KINC_FUNC bool kinc_socket_set_block(kinc_socket_t *sock, bool block);
KINC_FUNC bool kinc_socket_set_broadcast(kinc_socket_t *sock);
KINC_FUNC bool kinc_socket_set_nodelay(kinc_socket_t *sock);

KINC_FUNC int kinc_socket_recv(kinc_socket_t *sock, char *buf, int len, int flags);
KINC_FUNC int kinc_socket_send(kinc_socket_t *sock, char *buf, int len, int flags);

KINC_FUNC int kinc_socket_recvfrom(kinc_socket_t *sock, char *buf, int len, int flags, int *host, int *port);
KINC_FUNC int kinc_socket_sendto(kinc_socket_t *sock, int host, int port, char *buf, int len, int flags);

KINC_FUNC int kinc_socket_shutdown(kinc_socket_t *sock, bool r, bool w);
KINC_FUNC int kinc_socket_close(kinc_socket_t *sock);

#ifdef __cplusplus
}
#endif
