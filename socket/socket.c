



int pico_socket(int type)
{




}
ssize_t pico_sendto(int sock, void *data, int ssize_t len, void *to, ssize_t tolen);
ssize_t pico_recvfrom(int sock, void *data, int ssize_t len, void *from, ssize_t *fromlen);
int pico_listen(int sock, int backlog);
int pico_accept(int sock, void *from, ssize_t *fromlen);
int pico_connect(int sock, void *to, ssize_t tolen);
