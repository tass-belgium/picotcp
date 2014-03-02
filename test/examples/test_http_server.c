/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_nat.h"
#include "pico_icmp4.h"
#include "pico_dns_client.h"
#include "pico_dev_loop.h"
#include "pico_dhcp_client.h"
#include "pico_dhcp_server.h"
#include "pico_ipfilter.h"
#include "pico_http_client.h"
#include "pico_http_server.h"
#include "pico_http_util.h"
#include "pico_zmq.h"
#include "pico_olsr.h"
#include "pico_slaacv4.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

static struct pico_ip4 ZERO_IP4 = {
    0
};

static char *url_filename = NULL;

/* #define INFINITE_TCPTEST */
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */

/* #define PICOAPP_IPFILTER 1 */

struct pico_ip4 inaddr_any = {
    0
};

static char *cpy_arg(char **dst, char *str);
void wget_callback(uint16_t ev, uint16_t conn);

/*** START HTTP server ***/
#define SIZE 4 * 1024

void serverWakeup(uint16_t ev, uint16_t conn)
{
    static FILE *f;
    char buffer[SIZE];

    if(ev & EV_HTTP_CON)
    {
        printf("New connection received....\n");
        pico_http_server_accept();
    }

    if(ev & EV_HTTP_REQ) /* new header received */
    {
        uint16_t read;
        char *resource;
        int method;
        printf("Header request was received...\n");
        printf("> Resource : %s\n", pico_http_getResource(conn));
        resource = pico_http_getResource(conn);
        method = pico_http_getMethod(conn);

        if(strcmp(resource, "/") == 0 || strcmp(resource, "index.html") == 0 || strcmp(resource, "/index.html") == 0)
        {
            if(method == HTTP_METHOD_GET)
            {
                /* Accepting request */
                printf("Received GET request\n");
                pico_http_respond(conn, HTTP_RESOURCE_FOUND);
                f = fopen("test/examples/form.html", "r");

                if(!f)
                {
                    fprintf(stderr, "Unable to open the file /test/examples/form.html\n");
                }

                read = (uint16_t)fread(buffer, 1u, SIZE, f);
                pico_http_submitData(conn, buffer, read);
            }
            else if(method == HTTP_METHOD_POST)
            {
                printf("Received POST request\n");
                printf("Form fields: %s\n", pico_http_getBody(conn));
                pico_http_respond(conn, HTTP_RESOURCE_FOUND);
                strcpy(buffer, "Thanks for posting your data");
                if(pico_http_submitData(conn, buffer, (uint16_t)strlen(buffer)) == HTTP_RETURN_ERROR)
                {
                    printf("error submitting data\n");
                }
                else
                {
                    printf("data submitted correctly\n");
                }
            }
        }
        else if(strcmp(resource, "/download") == 0)
        {
            const char download_url_field [] = "download_url=";
            char *download_url = NULL;
            char *download_basename = NULL;
            char *decoded_download_url = NULL;
            char *http_body = NULL;

            http_body = pico_http_getBody(conn);

            if(http_body != NULL)
            {
                download_url = strstr(http_body, download_url_field);
                if(download_url != NULL)
                {
                    download_url = download_url + strlen(download_url_field);
                    decoded_download_url = pico_zalloc(strlen(download_url) + 1);
                    url_decode(decoded_download_url, download_url);
                    printf("Download url: %s\n", decoded_download_url);

                    if(pico_http_client_open(decoded_download_url, wget_callback) < 0)
                    {
                        fprintf(stderr, " error opening the url : %s, please check the format\n", decoded_download_url);
                        pico_http_respond(conn, HTTP_RESOURCE_NOT_FOUND);
                    }

                    download_basename = basename(decoded_download_url);
                    url_filename = pico_zalloc(strlen(download_basename) + 1);
                    strcpy(url_filename, download_basename);

                    pico_free(decoded_download_url);

                    pico_http_respond(conn, HTTP_RESOURCE_FOUND);
                    strcpy(buffer, "Download started");
                    if(pico_http_submitData(conn, buffer, (uint16_t)strlen(buffer)) == HTTP_RETURN_ERROR)
                    {
                        printf("error submitting data\n");
                    }
                }
                else
                {
                    printf("no download url\n");
                    pico_http_respond(conn, HTTP_RESOURCE_NOT_FOUND);
                }
            }
            else
            {
                printf("no http body\n");
                pico_http_respond(conn, HTTP_RESOURCE_NOT_FOUND);
            }
        }
        else
        { /* reject */
            printf("Rejected connection...\n");
            pico_http_respond(conn, HTTP_RESOURCE_NOT_FOUND);
        }

    }

    if(ev & EV_HTTP_PROGRESS) /* submitted data was sent */
    {
        uint16_t sent, total;
        pico_http_getProgress(conn, &sent, &total);
        printf("Chunk statistics : %d/%d sent\n", sent, total);
    }

    if(ev & EV_HTTP_SENT) /* submitted data was fully sent */
    {
        int method;
        method = pico_http_getMethod(conn);
        if(method == HTTP_METHOD_GET)
        {
            uint16_t read;
            read = (uint16_t)fread(buffer, 1, SIZE, f);
            printf("Chunk was sent...\n");
            if(read > 0)
            {
                printf("Sending another chunk...\n");
                pico_http_submitData(conn, buffer, read);
            }
            else
            {
                printf("Last chunk get !\n");
                pico_http_submitData(conn, NULL, 0); /* send the final chunk */
                fclose(f);
            }
        }
        else if(method == HTTP_METHOD_POST)
        {
            printf("Last chunk post !\n");
            pico_http_submitData(conn, NULL, 0); /* send the final chunk */
        }
    }

    if(ev & EV_HTTP_CLOSE)
    {
        printf("Close request...\n");
        pico_http_close(conn);
    }

    if(ev & EV_HTTP_ERROR)
    {
        printf("Error on server...\n");
        pico_http_close(conn);
    }
}
/* END HTTP server */

/*** START HTTP Client ***/
static int http_open_file()
{
    int fd;
    printf("Opening file : %s\n", url_filename);
    fd = open(url_filename, O_WRONLY | O_CREAT | O_TRUNC, 0660);
    return fd;
}

static int http_save_file(int fd, void *data, uint32_t len)
{
    int w;

    printf("Appending data to fd:%d : %s\n", fd, url_filename);

    if (fd < 0)
        return fd;

    w = (int)write(fd, data, len);
    return w;
}

static int http_close_file(int fd)
{
    printf("Closing file : %s\n", url_filename);
    return close(fd);
}

void wget_callback(uint16_t ev, uint16_t conn)
{
    static char data[1024 * 128]; /* Buffer: 128kb */
    static uint32_t _length = 0u;
    static uint32_t _length_tot = 0u;
    static uint32_t start_time = 0u;
    static int fd = -1;

    if(ev & EV_HTTP_CON)
    {
        printf("Connected to the download server\n");
        start_time = PICO_TIME_MS();
        pico_http_client_sendHeader(conn, NULL, HTTP_HEADER_DEFAULT);
        _length = 0u;
    }

    if(ev & EV_HTTP_REQ)
    {
        struct pico_http_header *header = pico_http_client_readHeader(conn);
        printf("Received header from server...\n");
        printf("Server response : %d\n", header->responseCode);
        printf("Location : %s\n", header->location);
        printf("Transfer-Encoding : %d\n", header->transferCoding);
        printf("Size/Chunk : %d\n", header->contentLengthOrChunk);
        fd = http_open_file();
    }

    if(ev & EV_HTTP_BODY)
    {
        int len;
        struct pico_http_header *header = pico_http_client_readHeader(conn);

        printf("Reading data... len=%d\n", _length_tot + _length);
        if (_length + 1024 >= sizeof(data))
        {
            http_save_file(fd, data, _length);
            _length_tot += _length;
            _length = 0u;
        }

        /* Read from buffer */
        while((len = pico_http_client_readData(conn, data + _length, 1024)) && len > 0)
        {
            _length += (uint32_t)len;
        }
        if(header->contentLengthOrChunk == _length)
            ev = EV_HTTP_CLOSE;
    }


    if(ev & EV_HTTP_CLOSE)
    {
        struct pico_http_header *header = pico_http_client_readHeader(conn);
        int len;
        uint32_t speed;
        printf("Connection was closed...\n");
        printf("Reading remaining data, if any ...\n");
        if(!header)
        {
            printf("No header received\n");
            pico_http_client_close(conn);
        }

        /* first save any open read bytes */
        http_save_file(fd, data, _length);
        _length_tot += _length;
        _length = 0u;

        while((len = pico_http_client_readData(conn, data + _length, 1000u)) && len > 0)
        {
            _length += (uint32_t)len;
        }
        printf("Read a total data of : %d bytes \n", _length_tot);

        if(header->transferCoding == HTTP_TRANSFER_CHUNKED)
        {
            if(header->contentLengthOrChunk)
            {
                printf("Last chunk data not fully read !\n");
                exit(1);
            }
            else
            {
                printf("Transfer ended with a zero chunk! OK !\n");
            }
        }
        else
        {
            if(header->contentLengthOrChunk == (_length + _length_tot))
            {
                printf("Received the full : %d \n", _length + _length_tot);
            }
            else
            {
                printf("Received %d , waiting for %d\n", _length + _length_tot, header->contentLengthOrChunk);
            }
        }

        if (!url_filename) {
            printf("Failed to get local filename\n");
        }

        len = http_save_file(fd, data, _length);
        http_close_file(fd);
        if ((len < 0) || ((uint32_t)len < _length)) {
            printf("Failed to save file: %s\n", strerror(errno));
        }

        speed = _length_tot / (PICO_TIME_MS() - start_time) * 8;
        printf("Download speed: %d kbps\n", speed);

        pico_http_client_close(conn);
        pico_free(url_filename);
    }

    if(ev & EV_HTTP_ERROR)
    {
        printf("Connection error (probably dns failed : check the routing table), trying to close the client...\n");
        pico_http_client_close(conn);
    }

    if(ev & EV_HTTP_DNS)
    {
        printf("The DNS query was successful ... \n");
    }
}
/* END HTTP client */

#define NXT_MAC(x) ++ x[5]

/* Copy a string until the separator,
   terminate it and return the next index,
   or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
    char *p, *nxt = NULL;
    char *start = str;
    char *end = start + strlen(start);
    p = str;
    while (p) {
        if ((*p == ':') || (*p == '\0')) {
            *p = (char)0;
            nxt = p + 1;
            if ((*nxt == 0) || (nxt >= end))
                nxt = 0;

            printf("dup'ing %s\n", start);
            *dst = strdup(start);
            break;
        }

        p++;
    }
    return nxt;
}

int main(int argc, char **argv)
{
    unsigned char macaddr[6] = {
        0, 0, 0, 0xa, 0xb, 0x0
    };
    uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
    struct pico_device *dev = NULL;

    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"vde", 1, 0, 'v'},
        {"barevde", 1, 0, 'b'},
        {"tun", 1, 0, 't'},
        {"route", 1, 0, 'r'},
        {"app", 1, 0, 'a'},
        {"loop", 0, 0, 'l'},
        {0, 0, 0, 0}
    };
    int option_idx = 0;
    int c;

    *macaddr_low ^= (uint16_t)getpid();
    printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);

    pico_stack_init();
    /* Parse args */
    while(1) {
        c = getopt_long(argc, argv, "v:b:t:a:r:hl", long_options, &option_idx);
        if (c < 0)
            break;

        switch(c) {
        case 'v':
        {
            char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
            struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;
            printf("+++ OPTARG %s\n", optarg);
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&sock, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&addr, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&nm, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&gw, nxt);
            } while(0);
            if (!nm) {
                fprintf(stderr, "Vde: bad configuration...\n");
                exit(1);
            }

            dev = pico_vde_create(sock, name, macaddr);
            NXT_MAC(macaddr);
            if (!dev) {
                perror("Creating vde");
                exit(1);
            }

            printf("Vde created.\n");
            pico_string_to_ipv4(addr, &ipaddr.addr);
            pico_string_to_ipv4(nm, &netmask.addr);
            pico_ipv4_link_add(dev, ipaddr, netmask);
            /* bcastAddr.addr = (ipaddr.addr) | (~netmask.addr); */
            if (gw && *gw) {
                pico_string_to_ipv4(gw, &gateway.addr);
                pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
            }
        }
        break;
        }
    }
    if( pico_http_server_start(0, serverWakeup) < 0)
    {
        fprintf(stderr, "Unable to start the HTTP server on port 80\n");
    } else {
        printf("HTTP server started\n");
    }

    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
