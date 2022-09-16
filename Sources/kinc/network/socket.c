#include "socket.h"
#include <bits/stdint-uintn.h>
#include <kinc/libs/stb_sprintf.h>
#include <kinc/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
#include <Ws2tcpip.h>
#include <winsock2.h>
#elif defined(KORE_POSIX)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <unistd.h>
#endif

#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
static int counter = 0;
#endif

/*
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
// Important: Must be cleaned with freeaddrinfo(address) later if the result is 0 in order to prevent memory leaks
static int resolveAddress(const char *url, int port, struct addrinfo **result) {
	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	char serv[6];
	stbsp_sprintf(serv, "%u", port);
	return getaddrinfo(url, serv, &hints, result);
}
#endif


unsigned kinc_url_to_int(const char *url, int port) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
	struct addrinfo *address = NULL;
	int res = resolveAddress(url, port, &address);
	if (res != 0) {
		kinc_log(KINC_LOG_LEVEL_ERROR, "Could not resolve address.");
		return -1;
	}
	unsigned fromAddress = ntohl(((struct sockaddr_in *)address->ai_addr)->sin_addr.S_un.S_addr);
	freeaddrinfo(address);
	return fromAddress;
#else
	return 0;
#endif
}
*/

static void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
/*
static int get_addrinfo(char *host, int port, struct addrinfo *hints, struct addrinfo *servinfo) {
    char _port[6];
	stbsp_sprintf(_port, "%u", port);
    if(getaddrinfo(host, _port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    return 0;
}
*/

int kinc_get_hostname(char *hostname, int size) {
#if defined(KORE_POSIX)
    return gethostname(hostname,size);
#else
    return 0;
#endif
}

int kinc_host_resolve(char *host) {
	int ip = inet_addr(host);
	if (ip == INADDR_NONE) {
		struct hostent *h;
		h = gethostbyname((char *)host);
		ip = *((unsigned int *)h->h_addr_list[0]);
	}
	return ip;
}

char *kinc_host_to_string(int ip) {
	struct in_addr i;
	*(int *)&i = ip;
	char *c = inet_ntoa(i);
	return c;
}

int kinc_socket_connect(kinc_socket_t *sock, char *host, int port, int type, int family) {
    int fd, rv;
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = (type == 0) ? SOCK_STREAM : type;
    hints.ai_family = (family == 0) ? AF_UNSPEC : family;
    char _port[6];
	stbsp_sprintf(_port, "%u", port);
    if((rv = getaddrinfo(host, _port, &hints, &servinfo)) != 0)
        return rv;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            perror("client: connect");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo); 
    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }
    // addr = p;
    //char s[ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];
    char s[INET_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
    printf("client: connecting to %s\n", s);
    sock->handle = fd;
    return 0;
}

int kinc_socket_bind(kinc_socket_t *sock, char *host, int port, int type, int family) {
    int fd, rv;
    //int yes = 1;
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = (type == 0) ? SOCK_STREAM : type;
    hints.ai_family = (family == 0) ? AF_UNSPEC : family;
    if(host == NULL) hints.ai_flags = AI_PASSIVE;
    char _port[6];
	stbsp_sprintf(_port, "%u", port);
    if((rv = getaddrinfo(host, _port, &hints, &servinfo)) != 0)
        return rv;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        // if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        //     perror("setsockopt");
        //     return 1;
        // }
        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            perror("server: bind");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if(p == NULL)
        return 1;
    sock->handle = fd;
    return 0;
}

bool kinc_socket_listen(kinc_socket_t *sock, unsigned int backlog) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
	int r = listen(sock->handle, backlog);
    return r == 0;
#else
	return false;
#endif
}

bool kinc_socket_accept(kinc_socket_t *server, kinc_socket_t *client, uint32_t *remoteAddress, uint16_t *remotePort) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
	typedef int socklen_t;
#endif
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof addr;
    if((fd = accept(server->handle, (struct sockaddr *)&addr, &addr_size)) == -1)
        return false;
    client->handle = fd;
	*remoteAddress = ntohl(addr.sin_addr.s_addr);
	*remotePort = ntohs(addr.sin_port);
    return true;
#else
    return false;
#endif
}

/*
TODO
bool kinc_socket_select(int max) {
   //select(max+1, ra, wa, ea);
   return false;
}
*/

bool kinc_socket_set_block(kinc_socket_t *sock, bool block) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
	DWORD value = 1;
	if (ioctlsocket(sock->handle, FIONBIO, &value) != 0) {
		kinc_log(KINC_LOG_LEVEL_ERROR, "Could not set non-blocking mode.");
		return false;
	}
#elif defined(KORE_POSIX)
    int rights;
    rights = fcntl(sock->handle,F_GETFL);
    if( rights == -1 )
        return false;
    if( block )
		rights &= ~O_NONBLOCK;
    else
		rights |= O_NONBLOCK;
    int r = fcntl(sock->handle, F_SETFL, rights);
    return r != -1;
	/* int value = 1;
	if (fcntl(sock->handle, F_SETFL, O_NONBLOCK, value) == -1) {
		kinc_log(KINC_LOG_LEVEL_ERROR, "Could not set non-blocking mode.");
		// return false;
	} */
#else
    return false;
#endif
}

bool kinc_socket_set_broadcast(kinc_socket_t *sock) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
    int value = 1;
    if (setsockopt(sock->handle, SOL_SOCKET, SO_BROADCAST, (const char *)&value, sizeof(value)) < 0) {
        kinc_log(KINC_LOG_LEVEL_ERROR, "Could not set broadcast mode.");
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool kinc_socket_set_nodelay(kinc_socket_t *sock) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
	int value = 1;
	if (setsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, (const char *)&value, sizeof(value)) != 0) {
		kinc_log(KINC_LOG_LEVEL_ERROR, "Could not set no-delay mode.");
		return false;
	}
    return true;
#else
    return false;
#endif
}

int kinc_socket_recv(kinc_socket_t *sock, char *buf, int len, int flags) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
	return recv(sock->handle, buf, len, flags);
#else
    return 0;
#endif
}

int kinc_socket_send(kinc_socket_t *sock, char *buf, int len, int flags) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
	return send(sock->handle, buf, len, flags);
#else
	return 0;
#endif
}

int kinc_socket_recvfrom(kinc_socket_t *sock, char *buf, int size, int flags, int *host, int *port) {
    struct sockaddr_in from;
	socklen_t fromlen = sizeof from;
    ssize_t bytes = recvfrom(sock->handle, buf, size, flags, (struct sockaddr *)&from, &fromlen);
    *host = from.sin_addr.s_addr;
    *port = from.sin_port;
	return (int)bytes;
}

int kinc_socket_sendto(kinc_socket_t *sock, int host, int port, char *buf, int len, int flags) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    //addr.sin_port = htons(port);
    //addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = port;
    addr.sin_addr.s_addr = host;
    return sendto(sock->handle, buf, len, 0, (struct sockaddr*)&addr, sizeof(addr)); 
#endif
}

int kinc_socket_shutdown(kinc_socket_t *sock, bool r, bool w) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP) || defined(KORE_POSIX)
    if( !r && !w )
		return 2;
    return shutdown(sock->handle, r ? (w ? SHUT_RDWR : SHUT_RD) : SHUT_WR);
#else
    return 1;
#endif
}

int kinc_socket_close(kinc_socket_t *sock) {
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
    int err = closesocket(sock->handle);
#elif defined(KORE_POSIX)
    int err = close(sock->handle);
#endif
    sock->handle = 0;
#if defined(KORE_WINDOWS) || defined(KORE_WINDOWSAPP)
    if (--counter == 0) {
        WSACleanup();
    }
#endif
    return err;
}

