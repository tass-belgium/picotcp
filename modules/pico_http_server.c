/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/

#include "pico_stack.h"
#include "pico_http_server.h"
#include "pico_tcp.h"
#include "pico_tree.h"
#include "pico_socket.h"

#ifdef PICO_SUPPORT_HTTP_SERVER

#define BACKLOG                             10

#define HTTP_SERVER_CLOSED      0
#define HTTP_SERVER_LISTEN      1

#define HTTP_HEADER_MAX_LINE    256u

#define consumeChar(c) (pico_socket_read(client->sck, &c, 1u))

static const char returnOkHeader[] =
    "HTTP/1.1 200 OK\r\n\
Host: localhost\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\
\r\n";

static const char returnFailHeader[] =
    "HTTP/1.1 404 Not Found\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n\
<html><body>The resource you requested cannot be found !</body></html>";

static const char errorHeader[] =
    "HTTP/1.1 400 Bad Request\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n\
<html><body>There was a problem with your request !</body></html>";

struct httpServer
{
    uint16_t state;
    struct pico_socket *sck;
    uint16_t port;
    void (*wakeup)(uint16_t ev, uint16_t param);
    uint8_t accepted;
};

struct httpClient
{
    uint16_t connectionID;
    struct pico_socket *sck;
    void *buffer;
    uint16_t bufferSize;
    uint16_t bufferSent;
    char *resource;
    uint16_t state;
};

/* Local states for clients */
#define HTTP_WAIT_HDR               0
#define HTTP_WAIT_EOF_HDR       1
#define HTTP_EOF_HDR                2
#define HTTP_WAIT_RESPONSE  3
#define HTTP_WAIT_DATA          4
#define HTTP_SENDING_DATA       5
#define HTTP_ERROR                  6
#define HTTP_CLOSED                 7

static struct httpServer server = {
    0
};

/*
 * Private functions
 */
static int parseRequest(struct httpClient *client);
static int readRemainingHeader(struct httpClient *client);
static void sendData(struct httpClient *client);
static inline int readData(struct httpClient *client);  /* used only in a place */
static inline struct httpClient *findClient(uint16_t conn);

static int compareClients(void *ka, void *kb)
{
    return ((struct httpClient *)ka)->connectionID - ((struct httpClient *)kb)->connectionID;
}

PICO_TREE_DECLARE(pico_http_clients, compareClients);

void httpServerCbk(uint16_t ev, struct pico_socket *s)
{
    struct pico_tree_node *index;
    struct httpClient *client = NULL;
    uint8_t serverEvent = FALSE;

    /* determine the client for the socket */
    if( s == server.sck)
    {
        serverEvent = TRUE;
    }
    else
    {
        pico_tree_foreach(index, &pico_http_clients)
        {
            client = index->keyValue;
            if(client->sck == s) break;

            client = NULL;
        }
    }

    if(!client && !serverEvent)
    {
        return;
    }

    if (ev & PICO_SOCK_EV_RD)
    {

        if(readData(client) == HTTP_RETURN_ERROR)
        {
            /* send out error */
            client->state = HTTP_ERROR;
            pico_socket_write(client->sck, (const char *)errorHeader, sizeof(errorHeader) - 1);
            server.wakeup(EV_HTTP_ERROR, client->connectionID);
        }
    }

    if(ev & PICO_SOCK_EV_WR)
    {
        if(client->state == HTTP_SENDING_DATA)
        {
            sendData(client);
        }
    }

    if(ev & PICO_SOCK_EV_CONN)
    {
        server.accepted = FALSE;
        server.wakeup(EV_HTTP_CON, HTTP_SERVER_ID);
        if(!server.accepted)
        {
            pico_socket_close(s); /* reject socket */
        }
    }

    if((ev & PICO_SOCK_EV_CLOSE) || (ev & PICO_SOCK_EV_FIN))
    {
        server.wakeup(EV_HTTP_CLOSE, (uint16_t)(serverEvent ? HTTP_SERVER_ID : client->connectionID));
    }

    if(ev & PICO_SOCK_EV_ERR)
    {
        server.wakeup(EV_HTTP_ERROR, (uint16_t)(serverEvent ? HTTP_SERVER_ID : client->connectionID));
    }
}

/*
 * API for starting the server. If 0 is passed as a port, the port 80
 * will be used.
 */
int8_t pico_http_server_start(uint16_t port, void (*wakeup)(uint16_t ev, uint16_t conn))
{
    struct pico_ip4 anything = {
        0
    };

    server.port = (uint16_t)(port ? short_be(port) : short_be(80u));

    if(!wakeup)
    {
        pico_err = PICO_ERR_EINVAL;
        return HTTP_RETURN_ERROR;
    }

    server.sck = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &httpServerCbk);

    if(!server.sck)
    {
        pico_err = PICO_ERR_EFAULT;
        return HTTP_RETURN_ERROR;
    }

    if(pico_socket_bind(server.sck, &anything, &server.port) != 0)
    {
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return HTTP_RETURN_ERROR;
    }

    if (pico_socket_listen(server.sck, BACKLOG) != 0)
    {
        pico_err = PICO_ERR_EADDRINUSE;
        return HTTP_RETURN_ERROR;
    }

    server.wakeup = wakeup;
    server.state = HTTP_SERVER_LISTEN;
    return HTTP_RETURN_OK;
}

/*
 * API for accepting new connections. This function should be
 * called when the event EV_HTTP_CON is triggered, if not called
 * when noticed the connection will be considered rejected and the
 * socket will be dropped.
 *
 * Returns the ID of the new connection or a negative value if error.
 */
int pico_http_server_accept(void)
{
    struct pico_ip4 orig;
    struct httpClient *client;
    uint16_t port;

    client = pico_zalloc(sizeof(struct httpClient));
    if(!client)
    {
        pico_err = PICO_ERR_ENOMEM;
        return HTTP_RETURN_ERROR;
    }

    client->sck = pico_socket_accept(server.sck, &orig, &port);

    if(!client->sck)
    {
        pico_err = PICO_ERR_ENOMEM;
        pico_free(client);
        return HTTP_RETURN_ERROR;
    }

    server.accepted = TRUE;
    /* buffer used for async sending */
    client->state = HTTP_WAIT_HDR;
    client->buffer = NULL;
    client->bufferSize = 0;
    client->connectionID = pico_rand() & 0x7FFF;

    /* add element to the tree, if duplicate because the rand */
    /* regenerate */
    while(pico_tree_insert(&pico_http_clients, client) != NULL)
        client->connectionID = pico_rand() & 0x7FFF;
    return client->connectionID;
}

/*
 * Function used for getting the resource asked by the
 * client. It is useful after the request header (EV_HTTP_REQ)
 * from client was received, otherwise NULL is returned.
 */
char *pico_http_getResource(uint16_t conn)
{
    struct httpClient *client = findClient(conn);

    if(!client)
        return NULL;
    else
        return client->resource;
}

/*
 * After the resource was asked by the client (EV_HTTP_REQ)
 * before doing anything else, the server has to let know
 * the client if the resource can be provided or not.
 *
 * This is controlled via the code parameter which can
 * have two values :
 *
 * HTTP_RESOURCE_FOUND or HTTP_RESOURCE_NOT_FOUND
 *
 * If a resource is reported not found the 404 header will be sent and the connection
 * will be closed , otherwise the 200 header is sent and the user should
 * immediately submit data.
 *
 */
int pico_http_respond(uint16_t conn, uint16_t code)
{
    struct httpClient *client = findClient(conn);

    if(!client)
    {
        dbg("Client not found !\n");
        return HTTP_RETURN_ERROR;
    }

    if(client->state == HTTP_WAIT_RESPONSE)
    {
        if(code == HTTP_RESOURCE_FOUND)
        {
            client->state = HTTP_WAIT_DATA;
            return pico_socket_write(client->sck, (const char *)returnOkHeader, sizeof(returnOkHeader) - 1); /* remove \0 */
        }
        else
        {
            int length;

            length = pico_socket_write(client->sck, (const char *)returnFailHeader, sizeof(returnFailHeader) - 1); /* remove \0 */
            pico_socket_close(client->sck);
            client->state = HTTP_CLOSED;
            return length;

        }
    }
    else
    {
        dbg("Bad state for the client \n");
        return HTTP_RETURN_ERROR;
    }

}

/*
 * API used to submit data to the client.
 * Server sends data only using Transfer-Encoding: chunked.
 *
 * With this function the user will submit a data chunk to
 * be sent.
 * The function will send the chunk size in hex and the rest will
 * be sent using WR event from sockets.
 * After each transmision EV_HTTP_PROGRESS is called and at the
 * end of the chunk EV_HTTP_SENT is called.
 *
 * To let the client know this is the last chunk, the user
 * should pass a NULL buffer.
 */
int8_t pico_http_submitData(uint16_t conn, void *buffer, uint16_t len)
{

    struct httpClient *client = findClient(conn);
    char chunkStr[10];
    int chunkCount;

    if(client->state != HTTP_WAIT_DATA)
    {
        dbg("Client is in a different state than accepted\n");
        return HTTP_RETURN_ERROR;
    }

    if(client->buffer)
    {
        dbg("Already a buffer submited\n");
        return HTTP_RETURN_ERROR;
    }

    if(!client)
    {
        dbg("Wrong connection ID\n");
        return HTTP_RETURN_ERROR;
    }

    if(!buffer)
    {
        len = 0;
    }

    if(len > 0)
    {
        client->buffer = pico_zalloc(len);
        if(!client->buffer)
        {
            pico_err = PICO_ERR_ENOMEM;
            return HTTP_RETURN_ERROR;
        }

        /* taking over the buffer */
        memcpy(client->buffer, buffer, len);
    }
    else
        client->buffer = NULL;


    client->bufferSize = len;
    client->bufferSent = 0;

    /* create the chunk size and send it */
    if(len > 0)
    {
        client->state = HTTP_SENDING_DATA;
        chunkCount = pico_itoaHex(client->bufferSize, chunkStr);
        chunkStr[chunkCount++] = '\r';
        chunkStr[chunkCount++] = '\n';
        pico_socket_write(client->sck, chunkStr, chunkCount);
    }
    else if(len == 0)
    {
        dbg("->\n");
        /* end of transmision */
        pico_socket_write(client->sck, "0\r\n\r\n", 5u);
        /* nothing left, close the client */
        pico_socket_close(client->sck);
        client->state = HTTP_CLOSED;
    }

    return HTTP_RETURN_OK;
}

/*
 * When EV_HTTP_PROGRESS is triggered you can use this
 * function to check the state of the chunk.
 */

int pico_http_getProgress(uint16_t conn, uint16_t *sent, uint16_t *total)
{
    struct httpClient *client = findClient(conn);

    if(!client)
    {
        dbg("Wrong connection id !\n");
        return HTTP_RETURN_ERROR;
    }

    *sent = client->bufferSent;
    *total = client->bufferSize;

    return HTTP_RETURN_OK;
}

/*
 * This API can be used to close either a client
 * or the server ( if you pass HTTP_SERVER_ID as a connection ID).
 */
int pico_http_close(uint16_t conn)
{
    /* close the server */
    if(conn == HTTP_SERVER_ID)
    {
        if(server.state == HTTP_SERVER_LISTEN)
        {
            struct pico_tree_node *index, *tmp;
            /* close the server */
            pico_socket_close(server.sck);
            server.sck = NULL;

            /* destroy the tree */
            pico_tree_foreach_safe(index, &pico_http_clients, tmp)
            {
                struct httpClient *client = index->keyValue;

                if(client->resource)
                    pico_free(client->resource);

                pico_socket_close(client->sck);
                pico_tree_delete(&pico_http_clients, client);
            }

            server.state = HTTP_SERVER_CLOSED;
            return HTTP_RETURN_OK;
        }
        else /* nothing to close */
            return HTTP_RETURN_ERROR;
    } /* close a connection in this case */
    else
    {

        struct httpClient *client = findClient(conn);

        if(!client)
        {
            dbg("Client not found..\n");
            return HTTP_RETURN_ERROR;
        }

        pico_tree_delete(&pico_http_clients, client);

        if(client->resource)
            pico_free(client->resource);

        if(client->buffer)
            pico_free(client->buffer);

        if(client->state != HTTP_CLOSED || !client->sck)
            pico_socket_close(client->sck);

        pico_free(client);
        return HTTP_RETURN_OK;
    }
}

/* check the integrity of the request */
int parseRequest(struct httpClient *client)
{
    char c;
    /* read first line */
    consumeChar(c);
    if(c == 'G')
    { /* possible GET */

        char line[HTTP_HEADER_MAX_LINE];
        uint32_t index = 0;

        line[index] = c;

        /* consume the full line */
        while(consumeChar(c) > 0) /* read char by char only the first line */
        {
            line[++index] = c;
            if(c == '\n')
                break;

            if(index >= HTTP_HEADER_MAX_LINE)
            {
                dbg("Size exceeded \n");
                return HTTP_RETURN_ERROR;
            }
        }
        /* extract the function and the resource */
        if(memcmp(line, "GET", 3u) || line[3u] != ' ' || index < 10u || line[index] != '\n')
        {
            dbg("Wrong command or wrong ending\n");
            return HTTP_RETURN_ERROR;
        }

        /* start reading the resource */
        index = 4u; /* go after ' ' */
        while(line[index] != ' ')
        {
            if(line[index] == '\n') /* no terminator ' ' */
            {
                dbg("No terminator...\n");
                return HTTP_RETURN_ERROR;
            }

            index++;
        }
        client->resource = pico_zalloc(index - 3u); /* allocate without the GET in front + 1 which is \0 */

        if(!client)
        {
            pico_err = PICO_ERR_ENOMEM;
            return HTTP_RETURN_ERROR;
        }

        /* copy the resource */
        memcpy(client->resource, line + 4u, index - 4u); /* copy without the \0 which was already set by pico_zalloc */

        client->state = HTTP_WAIT_EOF_HDR;
        return HTTP_RETURN_OK;

    }

    return HTTP_RETURN_ERROR;
}



int readRemainingHeader(struct httpClient *client)
{
    char line[100];
    int count = 0;
    int len;

    while((len = pico_socket_read(client->sck, line, 100u)) > 0)
    {
        char c;
        int index = 0;
        /* parse the response */
        while(index < len)
        {
            c = line[index++];
            if(c != '\r' && c != '\n')
                count++;

            if(c == '\n')
            {
                if(!count)
                {
                    client->state = HTTP_EOF_HDR;
                    dbg("End of header !\n");
                    break;
                }

                count = 0;

            }
        }
    }
    return HTTP_RETURN_OK;
}

void sendData(struct httpClient *client)
{
    uint16_t length;
    while( client->bufferSent < client->bufferSize &&
           (length = (uint16_t)pico_socket_write(client->sck, client->buffer + client->bufferSent, client->bufferSize - client->bufferSent)) > 0 )
    {
        client->bufferSent = (uint16_t)(client->bufferSent + length);
        server.wakeup(EV_HTTP_PROGRESS, client->connectionID);
    }
    if(client->bufferSent == client->bufferSize && client->bufferSize)
    {
        /* send chunk trail */
        if(pico_socket_write(client->sck, "\r\n", 2) > 0)
        {
            client->state = HTTP_WAIT_DATA;
            /* free the buffer */
            pico_free(client->buffer);
            client->buffer = NULL;
            server.wakeup(EV_HTTP_SENT, client->connectionID);
        }
    }

}

int readData(struct httpClient *client)
{
    if(client->state == HTTP_WAIT_HDR)
    {
        if(parseRequest(client) < 0 || readRemainingHeader(client) < 0)
        {
            return HTTP_RETURN_ERROR;
        }
    } /* continue with this in case the header comes line by line not a big chunk */
    else if(client->state == HTTP_WAIT_EOF_HDR)
    {
        if(readRemainingHeader(client) < 0 )
            return HTTP_RETURN_ERROR;
    }

    if(client->state == HTTP_EOF_HDR)
    {
        client->state = HTTP_WAIT_RESPONSE;
        pico_socket_shutdown(client->sck, PICO_SHUT_RD);
        server.wakeup(EV_HTTP_REQ, client->connectionID);
    }

    return HTTP_RETURN_OK;
}

struct httpClient *findClient(uint16_t conn)
{
    struct httpClient dummy = {
        .connectionID = conn
    };

    return pico_tree_findKey(&pico_http_clients, &dummy);
}
#endif
