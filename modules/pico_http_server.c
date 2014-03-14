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

static const char returnOkCacheableHeader[] =
    "HTTP/1.1 200 OK\r\n\
Host: localhost\r\n\
Cache-control: public, max-age=86400\r\n\
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
    uint16_t method;
    char *body;
};

/* Local states for clients */
#define HTTP_WAIT_HDR               0
#define HTTP_WAIT_EOF_HDR           1
#define HTTP_EOF_HDR                2
#define HTTP_WAIT_RESPONSE          3
#define HTTP_WAIT_DATA              4
#define HTTP_WAIT_STATIC_DATA       5
#define HTTP_SENDING_DATA           6
#define HTTP_SENDING_STATIC_DATA    7
#define HTTP_SENDING_FINAL          8
#define HTTP_ERROR                  9
#define HTTP_CLOSED                 10

static struct httpServer server = {
    0
};

/*
 * Private functions
 */
static int parseRequest(struct httpClient *client);
static int readRemainingHeader(struct httpClient *client);
static void sendData(struct httpClient *client);
static void sendFinal(struct httpClient *client);
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
    uint8_t serverEvent = 0u;

    /* determine the client for the socket */
    if( s == server.sck)
    {
        serverEvent = 1u;
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
        if(client->state == HTTP_SENDING_DATA || client->state == HTTP_SENDING_STATIC_DATA)
        {
            sendData(client);
        }
        else if(client->state == HTTP_SENDING_FINAL)
        {
            sendFinal(client);
        }
    }

    if(ev & PICO_SOCK_EV_CONN)
    {
        server.accepted = 0u;
        server.wakeup(EV_HTTP_CON, HTTP_SERVER_ID);
        if(!server.accepted)
        {
            pico_socket_close(s); /* reject socket */
        }
    }

    if((ev & PICO_SOCK_EV_CLOSE) || (ev & PICO_SOCK_EV_FIN))
    {
        server.wakeup(EV_HTTP_CLOSE, (uint16_t)(serverEvent ? HTTP_SERVER_ID : (client->connectionID)));
    }

    if(ev & PICO_SOCK_EV_ERR)
    {
        server.wakeup(EV_HTTP_ERROR, (uint16_t)(serverEvent ? HTTP_SERVER_ID : (client->connectionID)));
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

    client = PICO_ZALLOC(sizeof(struct httpClient));
    if(!client)
    {
        pico_err = PICO_ERR_ENOMEM;
        return HTTP_RETURN_ERROR;
    }

    client->sck = pico_socket_accept(server.sck, &orig, &port);

    if(!client->sck)
    {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(client);
        return HTTP_RETURN_ERROR;
    }

    server.accepted = 1u;
    /* buffer used for async sending */
    client->state = HTTP_WAIT_HDR;
    client->buffer = NULL;
    client->bufferSize = 0;
    client->body = NULL;
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
 * Function used for getting the method coming from client
 * (e.g. POST, GET...)
 * Should only be used after header was read (EV_HTTP_REQ)
 */

int pico_http_getMethod(uint16_t conn)
{
    struct httpClient *client = findClient(conn);

    if(!client)
        return 0;
    else
        return client->method;
}

/*
 * Function used for getting the body of the request header
 * It is useful after a POST request header (EV_HTTP_REQ)
 * from client was received, otherwise NULL is returned.
 */
char *pico_http_getBody(uint16_t conn)
{
    struct httpClient *client = findClient(conn);

    if(!client)
        return NULL;
    else
        return client->body;
}


/*
 * After the resource was asked by the client (EV_HTTP_REQ)
 * before doing anything else, the server has to let know
 * the client if the resource can be provided or not.
 *
 * This is controlled via the code parameter which can
 * have three values :
 *
 * HTTP_RESOURCE_FOUND, HTTP_STATIC_RESOURCE_FOUND or HTTP_RESOURCE_NOT_FOUND
 *
 * If a resource is reported not found the 404 header will be sent and the connection
 * will be closed , otherwise the 200 header is sent and the user should
 * immediately submit (static) data.
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
        if(code & HTTP_RESOURCE_FOUND)
        {
            client->state = (code & HTTP_STATIC_RESOURCE) ? HTTP_WAIT_STATIC_DATA : HTTP_WAIT_DATA;
            if(code & HTTP_CACHEABLE_RESOURCE)
            {
                return pico_socket_write(client->sck, (const char *)returnOkCacheableHeader, sizeof(returnOkCacheableHeader) - 1); /* remove \0 */
            }
            else
            {
                return pico_socket_write(client->sck, (const char *)returnOkHeader, sizeof(returnOkHeader) - 1); /* remove \0 */
            }
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
 * be sent. If it's static data the function will not allocate a buffer.
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

    if(!client)
    {
        dbg("Wrong connection ID\n");
        return HTTP_RETURN_ERROR;
    }

    if(client->state != HTTP_WAIT_DATA && client->state != HTTP_WAIT_STATIC_DATA)
    {
        dbg("Client is in a different state than accepted\n");
        return HTTP_RETURN_ERROR;
    }

    if(client->buffer)
    {
        dbg("Already a buffer submited\n");
        return HTTP_RETURN_ERROR;
    }


    if(!buffer)
    {
        len = 0;
    }

    if(len > 0)
    {
        if(client->state == HTTP_WAIT_STATIC_DATA)
        {
            client->buffer = buffer;
        }
        else
        {
            client->buffer = PICO_ZALLOC(len);
            if(!client->buffer)
            {
                pico_err = PICO_ERR_ENOMEM;
                return HTTP_RETURN_ERROR;
            }

            /* taking over the buffer */
            memcpy(client->buffer, buffer, len);
        }
    }
    else
        client->buffer = NULL;


    client->bufferSize = len;
    client->bufferSent = 0;

    /* create the chunk size and send it */
    if(len > 0)
    {
        client->state = (client->state == HTTP_WAIT_DATA) ? HTTP_SENDING_DATA : HTTP_SENDING_STATIC_DATA;
        chunkCount = pico_itoaHex(client->bufferSize, chunkStr);
        chunkStr[chunkCount++] = '\r';
        chunkStr[chunkCount++] = '\n';
        pico_socket_write(client->sck, chunkStr, chunkCount);
    }
    else
    {
        sendFinal(client);
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
                    PICO_FREE(client->resource);

                if(client->body)
                    PICO_FREE(client->body);

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
            PICO_FREE(client->resource);

        if(client->state != HTTP_SENDING_STATIC_DATA && client->buffer)
            PICO_FREE(client->buffer);

        if(client->body)
            PICO_FREE(client->body);

        if(client->state != HTTP_CLOSED || !client->sck)
            pico_socket_close(client->sck);

        PICO_FREE(client);
        return HTTP_RETURN_OK;
    }
}

static int parseRequestConsumeFullLine(struct httpClient *client, char *line)
{
    char c = 0;
    uint32_t index = 0;
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
    return (int)index;
}

static int parseRequestExtractFunction(char *line, int index, const char *method)
{
    uint8_t len = (uint8_t)strlen(method);

    /* extract the function and the resource */
    if(memcmp(line, method, len) || line[len] != ' ' || index < 10 || line[index] != '\n')
    {
        dbg("Wrong command or wrong ending\n");
        return HTTP_RETURN_ERROR;
    }

    return 0;
}

static int parseRequestReadResource(struct httpClient *client, int method_length, char *line)
{
    uint32_t index;

    /* start reading the resource */
    index = (uint32_t)method_length + 1; /* go after ' ' */
    while(line[index] != ' ')
    {
        if(line[index] == '\n') /* no terminator ' ' */
        {
            dbg("No terminator...\n");
            return HTTP_RETURN_ERROR;
        }

        index++;
    }
    client->resource = PICO_ZALLOC(index - (uint32_t)method_length); /* allocate without the method in front + 1 which is \0 */

    if(!client->resource)
    {
        pico_err = PICO_ERR_ENOMEM;
        return HTTP_RETURN_ERROR;
    }

    /* copy the resource */
    memcpy(client->resource, line + method_length + 1, index - (uint32_t)method_length - 1); /* copy without the \0 which was already set by PICO_ZALLOC */
    return 0;
}

static int parseRequestGet(struct httpClient *client, char *line)
{
    int ret;

    ret = parseRequestConsumeFullLine(client, line);
    if(ret < 0)
        return ret;

    ret = parseRequestExtractFunction(line, ret, "GET");
    if(ret)
        return ret;

    ret = parseRequestReadResource(client, strlen("GET"), line);
    if(ret)
        return ret;

    client->state = HTTP_WAIT_EOF_HDR;
    client->method = HTTP_METHOD_GET;
    return HTTP_RETURN_OK;
}

static int parseRequestPost(struct httpClient *client, char *line)
{
    int ret;

    ret = parseRequestConsumeFullLine(client, line);
    if(ret < 0)
        return ret;

    ret = parseRequestExtractFunction(line, ret, "POST");
    if(ret)
        return ret;

    ret = parseRequestReadResource(client, strlen("POST"), line);
    if(ret)
        return ret;

    client->state = HTTP_WAIT_EOF_HDR;
    client->method = HTTP_METHOD_POST;
    return HTTP_RETURN_OK;
}

/* check the integrity of the request */
int parseRequest(struct httpClient *client)
{
    char c = 0;
    char line[HTTP_HEADER_MAX_LINE];
    /* read first line */
    consumeChar(c);
    line[0] = c;
    if(c == 'G')
    { /* possible GET */
        return parseRequestGet(client, line);
    }
    else if(c == 'P')
    { /* possible POST */
        return parseRequestPost(client, line);
    }

    return HTTP_RETURN_ERROR;
}

int readRemainingHeader(struct httpClient *client)
{
    char line[1000];
    int count = 0;
    int len;

    while((len = pico_socket_read(client->sck, line, 1000u)) > 0)
    {
        char c;
        int index = 0;
        uint32_t body_len = 0;
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

                    body_len = (uint32_t)(len - index);
                    if(body_len > 0)
                    {
                        client->body = PICO_ZALLOC(body_len + 1u);
                        if(client->body)
                        {
                            memcpy(client->body, line + index, body_len);
                        }
                        else
                        {
                            return HTTP_RETURN_ERROR;
                        }
                    }

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
           (length = (uint16_t)pico_socket_write(client->sck, (uint8_t *)client->buffer + client->bufferSent, \
                                                 client->bufferSize - client->bufferSent)) > 0 )
    {
        client->bufferSent = (uint16_t)(client->bufferSent + length);
        server.wakeup(EV_HTTP_PROGRESS, client->connectionID);
    }
    if(client->bufferSent == client->bufferSize && client->bufferSize)
    {
        /* send chunk trail */
        if(pico_socket_write(client->sck, "\r\n", 2) > 0)
        {
            /* free the buffer */
            if(client->state == HTTP_SENDING_DATA)
            {
                PICO_FREE(client->buffer);
            }

            client->buffer = NULL;

            client->state = HTTP_WAIT_DATA;
            server.wakeup(EV_HTTP_SENT, client->connectionID);
        }
    }

}

void sendFinal(struct httpClient *client)
{
    if(pico_socket_write(client->sck, "0\r\n\r\n", 5u) != 0)
    {
        pico_socket_close(client->sck);
        client->state = HTTP_CLOSED;
    }
    else
    {
        client->state = HTTP_SENDING_FINAL;
    }
}

int readData(struct httpClient *client)
{
    if(!client)
    {
        dbg("Wrong connection ID\n");
        return HTTP_RETURN_ERROR;
    }

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
