#ifndef _PICOTCP_SOCKETS
#define _PICOTCP_SOCKETS

#define PICOSOCK_STREAM 1
#define PICOSOCK_DGRAM  2

int pico_socket(int type);
ssize_t pico_sendto(int sock, void *data, int ssize_t len, void *to, ssize_t tolen);
ssize_t pico_recvfrom(int sock, void *data, int ssize_t len, void *from, ssize_t *fromlen);
int pico_listen(int sock, int backlog);
int pico_accept(int sock, void *from, ssize_t *fromlen);
int pico_connect(int sock, void *to, ssize_t tolen);

#define pico_send(sock, data, len) pico_sendto(sock, data, len, NULL, 0)
#define pico_recv(sock, data, len) pico_sendto(sock, data, len, NULL, NULL)




#endif
