/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/
#include <string.h>
#include <stdint.h>
#include "pico_tree.h"
#include "pico_config.h"
#include "pico_socket.h"
#include "pico_tcp.h"
#include "pico_dns_client.h"
#include "pico_http_client.h"
#include "pico_ipv4.h"
#include "pico_stack.h"

/*
 * This is the size of the following header
 *
 * GET <resource> HTTP/1.1<CRLF>
 * Host: <host>:<port><CRLF>
 * User-Agent: picoTCP<CRLF>
 * Connection: close<CRLF>
 * <CRLF>
 *
 * where <resource>,<host> and <port> will be added later.
 */

#ifdef PICO_SUPPORT_HTTP_CLIENT

#define HTTP_GET_BASIC_SIZE   63u
#define HTTP_HEADER_LINE_SIZE 50u
#define RESPONSE_INDEX              9u

#define HTTP_CHUNK_ERROR    0xFFFFFFFFu

#ifdef dbg
    #undef dbg
#endif

#define dbg(...) do {} while(0)
#define nop() do {} while(0)

#define consumeChar(c)                          (pico_socket_read(client->sck, &c, 1u))
#define isLocation(line)                        (memcmp(line, "Location", 8u) == 0)
#define isContentLength(line)           (memcmp(line, "Content-Length", 14u) == 0u)
#define isTransferEncoding(line)        (memcmp(line, "Transfer-Encoding", 17u) == 0u)
#define isChunked(line)                         (memcmp(line, " chunked", 8u) == 0u)
#define isNotHTTPv1(line)                       (memcmp(line, "HTTP/1.", 7u))
#define is_hex_digit(x) ((('0' <= x) && (x <= '9')) || (('a' <= x) && (x <= 'f')))
#define hex_digit_to_dec(x) ((('0' <= x) && (x <= '9')) ? (x - '0') : ((('a' <= x) && (x <= 'f')) ? (x - 'a' + 10) : (-1)))

struct pico_http_client
{
    uint16_t connectionID;
    uint8_t state;
    struct pico_socket *sck;
    void (*wakeup)(uint16_t ev, uint16_t conn);
    struct pico_ip4 ip;
    struct pico_http_uri *uriKey;
    struct pico_http_header *header;
};

/* HTTP Client internal states */
#define HTTP_START_READING_HEADER      0
#define HTTP_READING_HEADER      1
#define HTTP_READING_BODY        2
#define HTTP_READING_CHUNK_VALUE 3
#define HTTP_READING_CHUNK_TRAIL 4

/* HTTP URI string parsing */
#define HTTP_PROTO_TOK      "http://"
#define HTTP_PROTO_LEN      7u

struct pico_http_uri
{
    uint8_t protoHttp; /* is the protocol Http ? */
    char *host;              /* hostname */
    uint16_t port;       /* port if specified */
    char *resource;      /* resource , ignoring the other possible parameters */
};

static int8_t pico_processURI(const char *uri, struct pico_http_uri *urikey)
{

    uint16_t lastIndex = 0, index;

    if(!uri || !urikey || uri[0] == '/')
    {
        pico_err = PICO_ERR_EINVAL;
        goto error;
    }

    /* detect protocol => search for  "colon-slash-slash" */
    if(memcmp(uri, HTTP_PROTO_TOK, HTTP_PROTO_LEN) == 0) /* could be optimized */
    { /* protocol identified, it is http */
        urikey->protoHttp = 1;
        lastIndex = HTTP_PROTO_LEN;
    }
    else
    {
        if(strstr(uri, "://")) /* different protocol specified */
        {
            urikey->protoHttp = 0;
            goto error;
        }

        /* no protocol specified, assuming by default it's http */
        urikey->protoHttp = 1;
    }

    /* detect hostname */
    index = lastIndex;
    while(uri[index] && uri[index] != '/' && uri[index] != ':') index++;
    if(index == lastIndex)
    {
        /* wrong format */
        urikey->host = urikey->resource = NULL;
        urikey->port = urikey->protoHttp = 0u;
        pico_err = PICO_ERR_EINVAL;
        goto error;
    }
    else
    {
        /* extract host */
        urikey->host = (char *)PICO_ZALLOC((uint32_t)(index - lastIndex + 1));

        if(!urikey->host)
        {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        memcpy(urikey->host, uri + lastIndex, (size_t)(index - lastIndex));
    }

    if(!uri[index])
    {
        /* nothing specified */
        urikey->port = 80u;
        urikey->resource = PICO_ZALLOC(2u);
        if (!urikey->resource) {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        urikey->resource[0] = '/';
        return HTTP_RETURN_OK;
    }
    else if(uri[index] == '/')
    {
        urikey->port = 80u;
    }
    else if(uri[index] == ':')
    {
        urikey->port = 0u;
        index++;
        while(uri[index] && uri[index] != '/')
        {
            /* should check if every component is a digit */
            urikey->port = (uint16_t)(urikey->port * 10 + (uri[index] - '0'));
            index++;
        }
    }

    /* extract resource */
    if(!uri[index])
    {
        urikey->resource = PICO_ZALLOC(2u);
        if (!urikey->resource) {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        urikey->resource[0] = '/';
    }
    else
    {
        lastIndex = index;
        while(uri[index] && uri[index] != '?' && uri[index] != '&' && uri[index] != '#') index++;
        urikey->resource = (char *)PICO_ZALLOC((size_t)(index - lastIndex + 1));

        if(!urikey->resource)
        {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        memcpy(urikey->resource, uri + lastIndex, (size_t)(index - lastIndex));
    }

    return HTTP_RETURN_OK;

error:
    if(urikey->resource)
    {
        PICO_FREE(urikey->resource);
        urikey->resource = NULL;
    }

    if(urikey->host)
    {
        PICO_FREE(urikey->host);
        urikey->host = NULL;
    }

    return HTTP_RETURN_ERROR;
}

static int compareClients(void *ka, void *kb)
{
    return ((struct pico_http_client *)ka)->connectionID - ((struct pico_http_client *)kb)->connectionID;
}

PICO_TREE_DECLARE(pico_client_list, compareClients);

/* Local functions */
static int parseHeaderFromServer(struct pico_http_client *client, struct pico_http_header *header);
static int readChunkLine(struct pico_http_client *client);
/*  */
static inline void processConnErrClose(uint16_t ev, struct pico_http_client *client)
{
    if (!client)
        return;

    if(ev & PICO_SOCK_EV_CONN)
        client->wakeup(EV_HTTP_CON, client->connectionID);

    if(ev & PICO_SOCK_EV_ERR)
    {
        client->wakeup(EV_HTTP_ERROR, client->connectionID);
    }

    if((ev & PICO_SOCK_EV_CLOSE) || (ev & PICO_SOCK_EV_FIN))
    {
        client->wakeup(EV_HTTP_CLOSE, client->connectionID);
    }
}

static inline void waitForHeader(struct pico_http_client *client)
{
    /* wait for header */
    int http_ret;

    http_ret = parseHeaderFromServer(client, client->header);
    if(http_ret < 0)
    {
        client->wakeup(EV_HTTP_ERROR, client->connectionID);
    }
    else if(http_ret == HTTP_RETURN_BUSY)
    {
        client->state = HTTP_READING_HEADER;
    }
    else if(http_ret == HTTP_RETURN_NOT_FOUND)
    {
        client->wakeup(EV_HTTP_REQ, client->connectionID);
    }
    else
    {
        /* call wakeup */
        if(client->header->responseCode != HTTP_CONTINUE)
        {
            client->wakeup(
                (client->header->responseCode == HTTP_OK) ?
                (EV_HTTP_REQ | EV_HTTP_BODY) :     /* data comes for sure only when 200 is received */
                EV_HTTP_REQ
                , client->connectionID);
        }
    }
}

static inline void treatReadEvent(struct pico_http_client *client)
{
    /* read the header, if not read */
    dbg("treat read event, client state: %d\n", client->state);
    if(client->state == HTTP_START_READING_HEADER)
    {
        /* wait for header */
        client->header = PICO_ZALLOC(sizeof(struct pico_http_header));
        if(!client->header)
        {
            pico_err = PICO_ERR_ENOMEM;
            return;
        }

        waitForHeader(client);
    }
    else if(client->state == HTTP_READING_HEADER)
    {
        waitForHeader(client);
    }
    else
    {
        /* just let the user know that data has arrived, if chunked data comes, will be treated in the */
        /* read api. */
        client->wakeup(EV_HTTP_BODY, client->connectionID);
    }
}

static void tcpCallback(uint16_t ev, struct pico_socket *s)
{

    struct pico_http_client *client = NULL;
    struct pico_tree_node *index;

    dbg("tcp callback (%d)\n", ev);

    /* find httpClient */
    pico_tree_foreach(index, &pico_client_list)
    {
        if(((struct pico_http_client *)index->keyValue)->sck == s )
        {
            client = (struct pico_http_client *)index->keyValue;
            break;
        }
    }

    if(!client)
    {
        dbg("Client not found...Something went wrong !\n");
        return;
    }

    processConnErrClose(ev, client);

    if(ev & PICO_SOCK_EV_RD)
    {
        treatReadEvent(client);

    }
}

/* used for getting a response from DNS servers */
static void dnsCallback(char *ip, void *ptr)
{
    struct pico_http_client *client = (struct pico_http_client *)ptr;

    if(!client)
    {
        dbg("Who made the request ?!\n");
        return;
    }

    if(ip)
    {
        client->wakeup(EV_HTTP_DNS, client->connectionID);

        /* add the ip address to the client, and start a tcp connection socket */
        pico_string_to_ipv4(ip, &client->ip.addr);
        client->sck = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &tcpCallback);
        if(!client->sck)
        {
            client->wakeup(EV_HTTP_ERROR, client->connectionID);
            return;
        }

        if(pico_socket_connect(client->sck, &client->ip, short_be(client->uriKey->port)) < 0)
        {
            client->wakeup(EV_HTTP_ERROR, client->connectionID);
            return;
        }

    }
    else
    {
        /* wakeup client and let know error occured */
        client->wakeup(EV_HTTP_ERROR, client->connectionID);

        /* close the client (free used heap) */
        pico_http_client_close(client->connectionID);
    }
}

/*
 * API used for opening a new HTTP Client.
 *
 * The accepted uri's are [http:]hostname[:port]/resource
 * no relative uri's are accepted.
 *
 * The function returns a connection ID >= 0 if successful
 * -1 if an error occured.
 */
int pico_http_client_open(char *uri, void (*wakeup)(uint16_t ev, uint16_t conn))
{
    struct pico_http_client *client;
    uint32_t ip = 0;

    client = PICO_ZALLOC(sizeof(struct pico_http_client));
    if(!client)
    {
        /* memory error */
        pico_err = PICO_ERR_ENOMEM;
        return HTTP_RETURN_ERROR;
    }

    client->wakeup = wakeup;
    client->connectionID = (uint16_t)pico_rand() & 0x7FFFu; /* negative values mean error, still not good generation */

    client->uriKey = PICO_ZALLOC(sizeof(struct pico_http_uri));

    if(!client->uriKey)
    {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(client);
        return HTTP_RETURN_ERROR;
    }

    pico_processURI(uri, client->uriKey);

    if(pico_tree_insert(&pico_client_list, client))
    {
        /* already in */
        pico_err = PICO_ERR_EEXIST;
        PICO_FREE(client->uriKey);
        PICO_FREE(client);
        return HTTP_RETURN_ERROR;
    }

    /* dns query */
    if(pico_string_to_ipv4(client->uriKey->host, &ip) == -1)
    {
        dbg("Querying : %s \n", client->uriKey->host);
        pico_dns_client_getaddr(client->uriKey->host, dnsCallback, client);
    }
    else
    {
        dbg("host already and ip address, no dns required");
        dnsCallback(client->uriKey->host, client);
    }

    /* return the connection ID */
    return client->connectionID;
}

/*
 * API for sending a header to the client.
 *
 * if hdr == HTTP_HEADER_RAW , then the parameter header
 * is sent as it is to client.
 *
 * if hdr == HTTP_HEADER_DEFAULT, then the parameter header
 * is ignored and the library will build the response header
 * based on the uri passed when opening the client.
 *
 */
int32_t pico_http_client_sendHeader(uint16_t conn, char *header, uint8_t hdr)
{
    struct pico_http_client search = {
        .connectionID = conn
    };
    struct pico_http_client *http = pico_tree_findKey(&pico_client_list, &search);
    int32_t length;
    if(!http)
    {
        dbg("Client not found !\n");
        return HTTP_RETURN_ERROR;
    }

    /* the api gives the possibility to the user to build the GET header */
    /* based on the uri passed when opening the client, less headache for the user */
    if(hdr == HTTP_HEADER_DEFAULT)
    {
        header = pico_http_client_buildHeader(http->uriKey);

        if(!header)
        {
            pico_err = PICO_ERR_ENOMEM;
            return HTTP_RETURN_ERROR;
        }
    }

    length = pico_socket_write(http->sck, (void *)header, (int)strlen(header));

    if(hdr == HTTP_HEADER_DEFAULT)
        PICO_FREE(header);

    return length;
}


/* / */

static inline int checkChunkLine(struct pico_http_client *client, int tmpLenRead)
{
    if(readChunkLine(client) == HTTP_RETURN_ERROR)
    {
        dbg("Probably the chunk is malformed or parsed wrong...\n");
        client->wakeup(EV_HTTP_ERROR, client->connectionID);
        return HTTP_RETURN_ERROR;
    }

    if(client->state != HTTP_READING_BODY || !tmpLenRead)
        return 0; /* force out */

    return 1;
}

static inline void updateContentLength(struct pico_http_client *client, int tmpLenRead )
{
    if(tmpLenRead > 0)
    {
        client->header->contentLengthOrChunk = client->header->contentLengthOrChunk - (uint32_t)tmpLenRead;
    }
}

static inline int readBody(struct pico_http_client *client, char *data, uint16_t size, int *lenRead, int *tmpLenRead)
{
    *tmpLenRead = 0;

    if(client->state == HTTP_READING_BODY)
    {

        /* if needed truncate the data */
        *tmpLenRead = pico_socket_read(client->sck, data + (*lenRead),
                                       (client->header->contentLengthOrChunk < ((uint32_t)(size - (*lenRead)))) ? ((int)client->header->contentLengthOrChunk) : (size - (*lenRead)));

        updateContentLength(client, *tmpLenRead);
        if(*tmpLenRead < 0)
        {
            /* error on reading */
            dbg(">>> Error returned pico_socket_read\n");
            pico_err = PICO_ERR_EBUSY;
            /* return how much data was read until now */
            return (*lenRead);
        }
    }

    *lenRead += *tmpLenRead;
    return 0;
}

static inline int readBigChunk(struct pico_http_client *client, char *data, uint16_t size, int *lenRead)
{
    int value;
    /* check if we need more than one chunk */
    if(size >= client->header->contentLengthOrChunk)
    {
        /* read the rest of the chunk, if chunk is done, proceed to the next chunk */
        while((uint16_t)(*lenRead) <= size)
        {
            int tmpLenRead = 0;
            if(readBody(client, data, size, lenRead, &tmpLenRead))
                return (*lenRead);

            if((value = checkChunkLine(client, tmpLenRead)) <= 0)
                return value;
        }
    }

    return 0;
}

static inline void readSmallChunk(struct pico_http_client *client, char *data, uint16_t size, int *lenRead)
{
    if(size < client->header->contentLengthOrChunk)
    {
        /* read the data from the chunk */
        *lenRead = pico_socket_read(client->sck, (void *)data, size);

        if(*lenRead)
            client->header->contentLengthOrChunk = client->header->contentLengthOrChunk - (uint32_t)(*lenRead);
    }
}
static inline int readChunkedData(struct pico_http_client *client, char *data, uint16_t size)
{
    int lenRead = 0;
    int value;
    /* read the chunk line */
    if(readChunkLine(client) == HTTP_RETURN_ERROR)
    {
        dbg("Probably the chunk is malformed or parsed wrong...\n");
        client->wakeup(EV_HTTP_ERROR, client->connectionID);
        return HTTP_RETURN_ERROR;
    }

    /* nothing to read, no use to try */
    if(client->state != HTTP_READING_BODY)
    {
        pico_err = PICO_ERR_EAGAIN;
        return HTTP_RETURN_OK;
    }


    readSmallChunk(client, data, size, &lenRead);
    value = readBigChunk(client, data, size, &lenRead);
    if(value)
        return value;

    return lenRead;
}

/*
 * API for reading received data.
 *
 * This api hides from the user if the transfer-encoding
 * was chunked or a full length was provided, in case of
 * a chunked transfer encoding will "de-chunk" the data
 * and pass it to the user.
 */
int32_t pico_http_client_readData(uint16_t conn, char *data, uint16_t size)
{
    struct pico_http_client dummy = {
        .connectionID = conn
    };
    struct pico_http_client *client = pico_tree_findKey(&pico_client_list, &dummy);

    if(!client)
    {
        dbg("Wrong connection id !\n");
        pico_err = PICO_ERR_EINVAL;
        return HTTP_RETURN_ERROR;
    }

    /* for the moment just read the data, do not care if it's chunked or not */
    if(client->header->transferCoding == HTTP_TRANSFER_FULL)
        return pico_socket_read(client->sck, (void *)data, size);
    else
        return readChunkedData(client, data, size);
}

/*
 * API for reading received data.
 *
 * Reads out the header struct received from server.
 */
struct pico_http_header *pico_http_client_readHeader(uint16_t conn)
{
    struct pico_http_client dummy = {
        .connectionID = conn
    };
    struct pico_http_client *client = pico_tree_findKey(&pico_client_list, &dummy);

    if(client)
    {
        return client->header;
    }
    else
    {
        /* not found */
        dbg("Wrong connection id !\n");
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
}

/*
 * API for reading received data.
 *
 * Reads out the uri struct after was processed.
 */
struct pico_http_uri *pico_http_client_readUriData(uint16_t conn)
{
    struct pico_http_client dummy = {
        .connectionID = conn
    };
    struct pico_http_client *client = pico_tree_findKey(&pico_client_list, &dummy);
    /*  */
    if(client)
        return client->uriKey;
    else
    {
        /* not found */
        dbg("Wrong connection id !\n");
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
}

/*
 * API for reading received data.
 *
 * Close the client.
 */
static inline void freeHeader(struct pico_http_client *toBeRemoved)
{
    if(toBeRemoved->header)
    {
        /* free space used */
        if(toBeRemoved->header->location)
            PICO_FREE(toBeRemoved->header->location);

        PICO_FREE(toBeRemoved->header);
    }
}

static inline void freeUri(struct pico_http_client *toBeRemoved)
{
    if(toBeRemoved->uriKey)
    {
        if(toBeRemoved->uriKey->host)
            PICO_FREE(toBeRemoved->uriKey->host);

        if(toBeRemoved->uriKey->resource)
            PICO_FREE(toBeRemoved->uriKey->resource);

        PICO_FREE(toBeRemoved->uriKey);
    }
}
int pico_http_client_close(uint16_t conn)
{
    struct pico_http_client *toBeRemoved = NULL;
    struct pico_http_client dummy = {
        0
    };
    dummy.connectionID = conn;

    dbg("Closing the client...\n");
    toBeRemoved = pico_tree_delete(&pico_client_list, &dummy);
    if(!toBeRemoved)
    {
        dbg("Warning ! Element not found ...");
        return HTTP_RETURN_ERROR;
    }

    /* close socket */
    if(toBeRemoved->sck)
        pico_socket_close(toBeRemoved->sck);

    freeHeader(toBeRemoved);
    freeUri(toBeRemoved);

    PICO_FREE(toBeRemoved);

    return 0;
}

/*
 * API for reading received data.
 *
 * Builds a GET header based on the fields on the uri.
 */
char *pico_http_client_buildHeader(const struct pico_http_uri *uriData)
{
    char *header;
    char port[6u]; /* 6 = max length of a uint16 + \0 */

    unsigned long headerSize = HTTP_GET_BASIC_SIZE;

    if(!uriData->host || !uriData->resource || !uriData->port)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /*  */
    headerSize = (headerSize + strlen(uriData->host));
    headerSize = (headerSize + strlen(uriData->resource));
    headerSize = (headerSize + pico_itoa(uriData->port, port) + 4u); /* 3 = size(CRLF + \0) */
    header = PICO_ZALLOC(headerSize);

    if(!header)
    {
        /* not enought memory */
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* build the actual header */
    strcpy(header, "GET ");
    strcat(header, uriData->resource);
    strcat(header, " HTTP/1.1\r\n");
    strcat(header, "Host: ");
    strcat(header, uriData->host);
    strcat(header, ":");
    strcat(header, port);
    strcat(header, "\r\n");
    strcat(header, "User-Agent: picoTCP\r\nConnection: close\r\n\r\n"); /* ? */

    return header;
}


/*  */
static inline void readFirstLine(struct pico_http_client *client, char *line, uint32_t *index)
{
    char c;

    /* read the first line of the header */
    while(consumeChar(c) > 0 && c != '\r')
    {
        if(*index < HTTP_HEADER_LINE_SIZE) /* truncate if too long */
            line[(*index)++] = c;
    }
    consumeChar(c); /* consume \n */
}

static inline void startReadingBody(struct pico_http_client *client, struct pico_http_header *header)
{

    if(header->transferCoding == HTTP_TRANSFER_CHUNKED)
    {
        /* read the first chunk */
        header->contentLengthOrChunk = 0;

        client->state = HTTP_READING_CHUNK_VALUE;
        readChunkLine(client);

    }
    else
        client->state = HTTP_READING_BODY;
}

static inline int parseLocAndCont(struct pico_http_client *client, struct pico_http_header *header, char *line, uint32_t *index)
{
    char c;
    /* Location: */

    if(isLocation(line))
    {
        *index = 0;
        while(consumeChar(c) > 0 && c != '\r')
        {
            line[(*index)++] = c;
        }
        /* allocate space for the field */
        header->location = PICO_ZALLOC((*index) + 1u);
        if(header->location)
        {
            memcpy(header->location, line, (*index));
            return 1;
        }
        else
        {
            return -1;
        }
    }    /* Content-Length: */
    else if(isContentLength(line))
    {
        header->contentLengthOrChunk = 0u;
        header->transferCoding = HTTP_TRANSFER_FULL;
        /* consume the first space */
        consumeChar(c);
        while(consumeChar(c) > 0 && c != '\r')
        {
            header->contentLengthOrChunk = header->contentLengthOrChunk * 10u + (uint32_t)(c - '0');
        }
        return 1;
    }    /* Transfer-Encoding: chunked */

    return 0;
}

static inline int parseTransferEncoding(struct pico_http_client *client, struct pico_http_header *header, char *line, uint32_t *index)
{
    char c;

    if(isTransferEncoding(line))
    {
        (*index) = 0;
        while(consumeChar(c) > 0 && c != '\r')
        {
            line[(*index)++] = c;
        }
        if(isChunked(line))
        {
            header->contentLengthOrChunk = 0u;
            header->transferCoding = HTTP_TRANSFER_CHUNKED;
        }

        return 1;
    } /* just ignore the line */

    return 0;
}


static inline int parseFields(struct pico_http_client *client, struct pico_http_header *header, char *line, uint32_t *index)
{
    char c;
    int ret_val;

    ret_val = parseLocAndCont(client, header, line, index);
    if(ret_val == 0)
    {
        if(!parseTransferEncoding(client, header, line, index))
        {
            while(consumeChar(c) > 0 && c != '\r') nop();
        }
    }
    else if (ret_val == -1)
    {
        return -1;
    }

    /* consume the next one */
    consumeChar(c);
    /* reset the index */
    (*index) = 0u;

    return 0;
}

static inline int parseRestOfHeader(struct pico_http_client *client, struct pico_http_header *header, char *line, uint32_t *index)
{
    char c;
    int read_len = 0;

    /* parse the rest of the header */
    read_len = consumeChar(c);
    if(read_len == 0)
        return HTTP_RETURN_BUSY;

    while(read_len > 0)
    {
        if(c == ':')
        {
            if(parseFields(client, header, line, index) == -1)
                return HTTP_RETURN_ERROR;
        }
        else if(c == '\r' && !(*index))
        {
            /* consume the \n */
            consumeChar(c);
            break;
        }
        else
        {
            line[(*index)++] = c;
        }

        read_len = consumeChar(c);
    }
    return HTTP_RETURN_OK;
}

static int parseHeaderFromServer(struct pico_http_client *client, struct pico_http_header *header)
{
    char line[HTTP_HEADER_LINE_SIZE];
    uint32_t index = 0;

    if(client->state == HTTP_START_READING_HEADER)
    {
        readFirstLine(client, line, &index);
        /* check the integrity of the response */
        /* make sure we have enough characters to include the response code */
        /* make sure the server response starts with HTTP/1. */
        if((index < RESPONSE_INDEX + 2u) || isNotHTTPv1(line))
        {
            /* wrong format of the the response */
            pico_err = PICO_ERR_EINVAL;
            return HTTP_RETURN_ERROR;
        }

        /* extract response code */
        header->responseCode = (uint16_t)((line[RESPONSE_INDEX] - '0') * 100 +
                                          (line[RESPONSE_INDEX + 1] - '0') * 10 +
                                          (line[RESPONSE_INDEX + 2] - '0'));
        if(header->responseCode == HTTP_NOT_FOUND)
        {
            return HTTP_RETURN_NOT_FOUND;
        }
        else if(header->responseCode >= HTTP_INTERNAL_SERVER_ERR)
        {
            /* invalid response type */
            header->responseCode = 0;
            return HTTP_RETURN_ERROR;
        }
    }

    dbg("Server response : %d \n", header->responseCode);

    if(parseRestOfHeader(client, header, line, &index) == HTTP_RETURN_BUSY)
        return HTTP_RETURN_BUSY;

    startReadingBody(client, header);
    dbg("End of header\n");
    return HTTP_RETURN_OK;

}

/* an async read of the chunk part, since in theory a chunk can be split in 2 packets */
static inline void setClientChunkState(struct pico_http_client *client)
{

    if(client->header->contentLengthOrChunk == 0 && client->state == HTTP_READING_BODY)
    {
        client->state = HTTP_READING_CHUNK_VALUE;
    }
}
static inline void readChunkTrail(struct pico_http_client *client)
{
    char c;

    if(client->state == HTTP_READING_CHUNK_TRAIL)
    {

        while(consumeChar(c) > 0 && c != '\n') nop();
        if(c == '\n') client->state = HTTP_READING_BODY;
    }
}
static inline void readChunkValue(struct pico_http_client *client)
{
    char c;

    while(consumeChar(c) > 0 && c != '\r' && c != ';')
    {
        if(is_hex_digit(c))
            client->header->contentLengthOrChunk = (client->header->contentLengthOrChunk << 4u) + (uint32_t)hex_digit_to_dec(c);
    }
    if(c == '\r' || c == ';') client->state = HTTP_READING_CHUNK_TRAIL;
}

static int readChunkLine(struct pico_http_client *client)
{
    setClientChunkState(client);

    if(client->state == HTTP_READING_CHUNK_VALUE)
    {
        readChunkValue(client);
    }

    readChunkTrail(client);

    return HTTP_RETURN_OK;
}
#endif
