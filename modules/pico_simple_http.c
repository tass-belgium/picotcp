/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/

#include "pico_config.h"
#include "pico_socket.h"
#include "pico_tcp.h"
#include "pico_ipv4.h"
#include "pico_simple_http.h"

/* The HTTP Server cannot be available without TCP support */
#if (defined PICO_SUPPORT_HTTP) && (defined PICO_SUPPORT_IPV4) && (defined PICO_SUPPORT_TCP)

#define HTTP_LISTEN_PORT    80u
#define HTTP_BACKLOG            5u
#define HTTP_HEADER_SIZE  256u

#define HTTP_SUCCESS            0
#define HTTP_ERROR              -1

static struct pico_socket *httpServer = NULL;
static char httpResponse[] =
    "HTTP/1.0 200 OK\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><head>\r\n\
<title>picoTCP Simple Http server</title>\r\n\
</head>\r\n\
<body>\r\n\
<h1>Hello world from picoTCP !!</h1>\r\n\
</body>\r\n";

static void httpEventCbk(uint16_t ev, struct pico_socket *self)
{
    static struct pico_socket *client = NULL;
    uint32_t peer;
    uint16_t port;
    int r;
    char buffer[HTTP_HEADER_SIZE];

    switch(ev)
    {
    case PICO_SOCK_EV_CONN:
        if(!client)
            client = pico_socket_accept(self, &peer, &port);

        break;

    case PICO_SOCK_EV_RD:
        /* do not check http integrity, just mark that the http header has arrived */
        /* prepare to send the response */
        r = pico_socket_recvfrom(self, buffer, HTTP_HEADER_SIZE, &peer, &port);
        if(r > 0 && memcmp(buffer, "GET", 3u) == 0u)
        {     /* it is an http header asking for data, return data and close */
            pico_socket_write(self, httpResponse, sizeof(httpResponse));
            pico_socket_close(self);
        }
        else
        {
            /* kill the connection, invalid header */
            pico_socket_close(self);
        }

        break;

    case PICO_SOCK_EV_ERR:
    case PICO_SOCK_EV_CLOSE:
        /* free the used socket */
        client = NULL;
        break;

    default:
        break;
    }
}

int pico_startHttpServer(struct pico_ip4 *address)
{

    uint16_t localHttpPort = short_be(HTTP_LISTEN_PORT);

    if(!pico_is_port_free(localHttpPort, PICO_PROTO_TCP, address, &pico_proto_ipv4))
    {
        pico_err = PICO_ERR_EADDRINUSE;
        return HTTP_ERROR;
    }

    httpServer = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, httpEventCbk);

    if(!httpServer)
    {
        pico_err = PICO_ERR_ENOMEM;
        return HTTP_ERROR;
    }

    /* both functions set the pico_err themselves. */
    if(pico_socket_bind(httpServer, address, &localHttpPort))
        return HTTP_ERROR;

    if(pico_socket_listen(httpServer, HTTP_BACKLOG))
        return HTTP_ERROR;

    return HTTP_SUCCESS;
}

int pico_stopHttpServer(void)
{
    if(!httpServer)
    {
        pico_err = PICO_ERR_EINVAL;
        return HTTP_ERROR;
    }

    if(pico_socket_close(httpServer))
    {
        /* no need to set the error here, function already set it */
        httpServer = NULL;
        return HTTP_ERROR;
    }

    httpServer = NULL;
    return HTTP_SUCCESS;
}

#endif


