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
#define RESPONSE_INDEX				9u

#define HTTP_CHUNK_ERROR	0xFFFFFFFFu

#ifdef dbg
	#undef dbg
	#define dbg(...) do{}while(0);
#endif

#define consumeChar(c) 							(pico_socket_read(client->sck,&c,1u))
#define isLocation(line) 						(memcmp(line,"Location",8u) == 0)
#define isContentLength(line) 			(memcmp(line,"Content-Length",14u) == 0u)
#define isTransferEncoding(line)		(memcmp(line,"Transfer-Encoding",17u) == 0u)
#define isChunked(line)							(memcmp(line," chunked",8u) == 0u)
#define isNotHTTPv1(line)						(memcmp(line,"HTTP/1.",7u))
#define is_hex_digit(x) ( ('0' <= x && x <= '9') || ('a' <= x && x <= 'f') )
#define hex_digit_to_dec(x) ( ('0' <= x && x <= '9') ? x-'0' : ( ('a' <= x && x <= 'f') ? x-'a' + 10 : -1) )

struct pico_http_client
{
	uint16_t connectionID;
	uint8_t state;
	struct pico_socket * sck;
	void (*wakeup)(uint16_t ev, uint16_t conn);
	struct pico_ip4 ip;
	struct pico_http_uri * uriKey;
	struct pico_http_header * header;
};

// HTTP Client internal states
#define HTTP_READING_HEADER      0
#define HTTP_READING_BODY				 1
#define HTTP_READING_CHUNK_VALUE 2
#define HTTP_READING_CHUNK_TRAIL 3


static int compareClients(void * ka, void * kb)
{
	return ((struct pico_http_client *)ka)->connectionID - ((struct pico_http_client *)kb)->connectionID;
}

PICO_TREE_DECLARE(pico_client_list,compareClients);

// Local functions
int parseHeaderFromServer(struct pico_http_client * client, struct pico_http_header * header);
int readChunkLine(struct pico_http_client * client);

void tcpCallback(uint16_t ev, struct pico_socket *s)
{

	struct pico_http_client * client = NULL;
	struct pico_tree_node * index;

	// find httpClient
	pico_tree_foreach(index,&pico_client_list)
	{
		if( ((struct pico_http_client *)index->keyValue)->sck == s )
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

	if(ev & PICO_SOCK_EV_CONN)
		client->wakeup(EV_HTTP_CON,client->connectionID);

	if(ev & PICO_SOCK_EV_RD)
	{

		// read the header, if not read
		if(client->state == HTTP_READING_HEADER)
		{
			// wait for header
			client->header = pico_zalloc(sizeof(struct pico_http_header));
			if(!client->header)
			{
				pico_err = PICO_ERR_ENOMEM;
				return;
			}

			// wait for header
			if(parseHeaderFromServer(client,client->header) < 0)
			{
				client->wakeup(EV_HTTP_ERROR,client->connectionID);
			}
			else
			{
				// call wakeup
				if(client->header->responseCode != HTTP_CONTINUE)
				{
					client->wakeup(
							client->header->responseCode == HTTP_OK ?
							EV_HTTP_REQ | EV_HTTP_BODY : // data comes for sure only when 200 is received
							EV_HTTP_REQ
							,client->connectionID);
				}
			}
		}
		else
		{
			// just let the user know that data has arrived, if chunked data comes, will be treated in the
			// read api.
			client->wakeup(EV_HTTP_BODY,client->connectionID);
		}
	}

	if(ev & PICO_SOCK_EV_ERR)
	{
		client->wakeup(EV_HTTP_ERROR,client->connectionID);
	}

	if( (ev & PICO_SOCK_EV_CLOSE) || (ev & PICO_SOCK_EV_FIN) )
	{
		client->wakeup(EV_HTTP_CLOSE,client->connectionID);
	}

}

// used for getting a response from DNS servers
static void dnsCallback(char *ip, void * ptr)
{
	struct pico_http_client * client = (struct pico_http_client *)ptr;

	if(!client)
	{
		dbg("Who made the request ?!\n");
		return;
	}

	if(ip)
	{
		client->wakeup(EV_HTTP_DNS,client->connectionID);

		// add the ip address to the client, and start a tcp connection socket
		pico_string_to_ipv4(ip,&client->ip.addr);
		pico_free(ip);
		client->sck = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &tcpCallback);
		if(!client->sck)
		{
			client->wakeup(EV_HTTP_ERROR,client->connectionID);
			return;
		}

		if(pico_socket_connect(client->sck,&client->ip,short_be(client->uriKey->port)) < 0)
		{
			client->wakeup(EV_HTTP_ERROR,client->connectionID);
			return;
		}

	}
	else
	{
		// wakeup client and let know error occured
		client->wakeup(EV_HTTP_ERROR,client->connectionID);

		// close the client (free used heap)
		pico_http_client_close(client->connectionID);
	}
}

/*
 * API used for opening a new HTTP Client.
 *
 * The accepted uri's are [http://]hostname[:port]/resource
 * no relative uri's are accepted.
 *
 * The function returns a connection ID >= 0 if successful
 * -1 if an error occured.
 */
int pico_http_client_open(char * uri, void (*wakeup)(uint16_t ev, uint16_t conn))
{
	struct pico_http_client * client;

	if(!wakeup)
	{
		pico_err = PICO_ERR_EINVAL;
		return HTTP_RETURN_ERROR;
	}

	client = pico_zalloc(sizeof(struct pico_http_client));
	if(!client)
	{
		// memory error
		pico_err = PICO_ERR_ENOMEM;
		return HTTP_RETURN_ERROR;
	}

	client->wakeup = wakeup;
	client->connectionID = (uint16_t)pico_rand() & 0x7FFFu; // negative values mean error, still not good generation

	client->uriKey = pico_zalloc(sizeof(struct pico_http_uri));

	if(!client->uriKey)
	{
		pico_err = PICO_ERR_ENOMEM;
		pico_free(client);
		return HTTP_RETURN_ERROR;
	}

	pico_processURI(uri,client->uriKey);

	if(pico_tree_insert(&pico_client_list,client))
	{
		// already in
		pico_err = PICO_ERR_EEXIST;
		pico_free(client->uriKey);
		pico_free(client);
		return HTTP_RETURN_ERROR;
	}

	// dns query
	dbg("Querying : %s \n",client->uriKey->host);
	pico_dns_client_getaddr(client->uriKey->host, dnsCallback,client);

	// return the connection ID
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
int pico_http_client_sendHeader(uint16_t conn, char * header, int hdr)
{
	struct pico_http_client search = {.connectionID = conn};
	struct pico_http_client * http = pico_tree_findKey(&pico_client_list,&search);
	int length ;
	if(!http)
	{
		dbg("Client not found !\n");
		return HTTP_RETURN_ERROR;
	}

	// the api gives the possibility to the user to build the GET header
	// based on the uri passed when opening the client, less headache for the user
	if(hdr == HTTP_HEADER_DEFAULT)
	{
		header = pico_http_client_buildHeader(http->uriKey);

		if(!header)
		{
			pico_err = PICO_ERR_ENOMEM;
			return HTTP_RETURN_ERROR;
		}
	}

	length = pico_socket_write(http->sck,(void *)header,strlen(header)+1);

	if(hdr == HTTP_HEADER_DEFAULT)
		pico_free(header);

	return length;
}

/*
 * API for reading received data.
 *
 * This api hides from the user if the transfer-encoding
 * was chunked or a full length was provided, in case of
 * a chunked transfer encoding will "de-chunk" the data
 * and pass it to the user.
 */
int pico_http_client_readData(uint16_t conn, char * data, uint16_t size)
{
	struct pico_http_client dummy = {.connectionID = conn};
	struct pico_http_client * client = pico_tree_findKey(&pico_client_list,&dummy);

	if(!client)
	{
		dbg("Wrong connection id !\n");
		pico_err = PICO_ERR_EINVAL;
		return HTTP_RETURN_ERROR;
	}

	// for the moment just read the data, do not care if it's chunked or not
	if(client->header->transferCoding == HTTP_TRANSFER_FULL)
		return pico_socket_read(client->sck,(void *)data,size);
	else
	{
		int lenRead = 0;

		// read the chunk line
		if(readChunkLine(client) == HTTP_RETURN_ERROR)
		{
			dbg("Probably the chunk is malformed or parsed wrong...\n");
			client->wakeup(EV_HTTP_ERROR,client->connectionID);
			return HTTP_RETURN_ERROR;
		}

		// nothing to read, no use to try
		if(client->state != HTTP_READING_BODY)
		{
			pico_err = PICO_ERR_EAGAIN;
			return HTTP_RETURN_OK;
		}

		// check if we need more than one chunk
		if(size >= client->header->contentLengthOrChunk)
		{
			// read the rest of the chunk, if chunk is done, proceed to the next chunk
			while(lenRead <= size)
			{
				int tmpLenRead = 0;

				if(client->state == HTTP_READING_BODY)
				{

					// if needed truncate the data
					tmpLenRead = pico_socket_read(client->sck,data + lenRead,
					client->header->contentLengthOrChunk < (uint32_t)(size-lenRead) ? client->header->contentLengthOrChunk : (uint32_t)(size-lenRead));

					if(tmpLenRead > 0)
					{
						client->header->contentLengthOrChunk -= tmpLenRead;
					}
					else if(tmpLenRead < 0)
					{
						// error on reading
						dbg(">>> Error returned pico_socket_read\n");
						pico_err = PICO_ERR_EBUSY;
						// return how much data was read until now
						return lenRead;
					}
				}

				lenRead += tmpLenRead;
				if(readChunkLine(client) == HTTP_RETURN_ERROR)
				{
					dbg("Probably the chunk is malformed or parsed wrong...\n");
					client->wakeup(EV_HTTP_ERROR,client->connectionID);
					return HTTP_RETURN_ERROR;
				}

				if(client->state != HTTP_READING_BODY || !tmpLenRead)  break;

			}
		}
		else
		{
			// read the data from the chunk
			lenRead = pico_socket_read(client->sck,(void *)data,size);

			if(lenRead)
				client->header->contentLengthOrChunk -= lenRead;
		}

		return lenRead;
	}
}

/*
 * API for reading received data.
 *
 * Reads out the header struct received from server.
 */
struct pico_http_header * pico_http_client_readHeader(uint16_t conn)
{
	struct pico_http_client dummy = {.connectionID = conn};
	struct pico_http_client * client = pico_tree_findKey(&pico_client_list,&dummy);

	if(client)
	{
		return client->header;
	}
	else
	{
		// not found
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
struct pico_http_uri * pico_http_client_readUriData(uint16_t conn)
{
	struct pico_http_client dummy = {.connectionID = conn};
	struct pico_http_client * client = pico_tree_findKey(&pico_client_list,&dummy);
	//
	if(client)
		return client->uriKey;
	else
	{
		// not found
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
int pico_http_client_close(uint16_t conn)
{
	struct pico_http_client * toBeRemoved = NULL;
	struct pico_http_client dummy = {0};
	dummy.connectionID = conn;

	dbg("Closing the client...\n");
	toBeRemoved = pico_tree_delete(&pico_client_list,&dummy);
	if(!toBeRemoved)
	{
		dbg("Warning ! Element not found ...");
		return HTTP_RETURN_ERROR;
	}

	// close socket
	if(toBeRemoved->sck)
	pico_socket_close(toBeRemoved->sck);


	if(toBeRemoved->header)
	{
		// free space used
			if(toBeRemoved->header->location)
				pico_free(toBeRemoved->header->location);

		pico_free(toBeRemoved->header);
	}

	if(toBeRemoved->uriKey)
	{
		if(toBeRemoved->uriKey->host)
			pico_free(toBeRemoved->uriKey->host);

		if(toBeRemoved->uriKey->resource)
			pico_free(toBeRemoved->uriKey->resource);
		pico_free(toBeRemoved->uriKey);
	}
	pico_free(toBeRemoved);

	return 0;
}

/*
 * API for reading received data.
 *
 * Builds a GET header based on the fields on the uri.
 */
char * pico_http_client_buildHeader(const struct pico_http_uri * uriData)
{
	char * header;
	char port[6u]; // 6 = max length of a uint16 + \0

	uint16_t headerSize = HTTP_GET_BASIC_SIZE;

	if(!uriData->host || !uriData->resource || !uriData->port)
	{
		pico_err = PICO_ERR_EINVAL;
		return NULL;
	}

	//
	headerSize += strlen(uriData->host) + strlen(uriData->resource) + pico_itoa(uriData->port,port) + 4u; // 3 = size(CRLF + \0)
	header = pico_zalloc(headerSize);

	if(!header)
	{
		// not enought memory
		pico_err = PICO_ERR_ENOMEM;
		return NULL;
	}

	// build the actual header
	strcpy(header,"GET ");
	strcat(header,uriData->resource);
	strcat(header," HTTP/1.1\r\n");
	strcat(header,"Host: ");
	strcat(header,uriData->host);
	strcat(header,":");
	strcat(header,port);
	strcat(header,"\r\n");
	strcat(header,"User-Agent: picoTCP\r\nConnection: close\r\n\r\n"); //?

	return header;
}

int parseHeaderFromServer(struct pico_http_client * client, struct pico_http_header * header)
{
	char line[HTTP_HEADER_LINE_SIZE];
	char c;
	uint32_t index = 0;

	// read the first line of the header
	while(consumeChar(c)>0 && c!='\r')
	{
		if(index < HTTP_HEADER_LINE_SIZE) // truncate if too long
			line[index++] = c;
	}

	consumeChar(c); // consume \n

	// check the integrity of the response
	// make sure we have enough characters to include the response code
	// make sure the server response starts with HTTP/1.
	if(index < RESPONSE_INDEX+2 || isNotHTTPv1(line))
	{
		// wrong format of the the response
		pico_err = PICO_ERR_EINVAL;
		return HTTP_RETURN_ERROR;
	}

	// extract response code
	header->responseCode = (line[RESPONSE_INDEX] - '0') * 100u +
												 (line[RESPONSE_INDEX+1] - '0') * 10u +
												 (line[RESPONSE_INDEX+2] - '0');


	if(header->responseCode/100u > 5u)
	{
		// invalid response type
		header->responseCode = 0;
		return HTTP_RETURN_ERROR;
	}

	dbg("Server response : %d \n",header->responseCode);

	// parse the rest of the header
	while(consumeChar(c)>0)
	{
		if(c==':')
		{
			// check for interesting fields

			// Location:
			if(isLocation(line))
			{
				index = 0;
				while(consumeChar(c)>0 && c!='\r')
				{
					line[index++] = c;
				}

				// allocate space for the field
				header->location = pico_zalloc(index+1u);
				if(!header->location)
				{
					pico_err = PICO_ERR_ENOMEM;
					return HTTP_RETURN_ERROR;
				}

				memcpy(header->location,line,index);

			}// Content-Length:
			else if(isContentLength(line))
			{
				header->contentLengthOrChunk = 0u;
				header->transferCoding = HTTP_TRANSFER_FULL;
				// consume the first space
				consumeChar(c);
				while(consumeChar(c)>0 && c!='\r')
				{
					header->contentLengthOrChunk = header->contentLengthOrChunk*10u + (c-'0');
				}

			}// Transfer-Encoding: chunked
			else if(isTransferEncoding(line))
			{
				index = 0;
				while(consumeChar(c)>0 && c!='\r')
				{
					line[index++] = c;
				}

				if(isChunked(line))
				{
					header->contentLengthOrChunk = 0u;
					header->transferCoding = HTTP_TRANSFER_CHUNKED;
				}

			}// just ignore the line
			else
			{
				while(consumeChar(c)>0 && c!='\r');
			}

			// consume the next one
			consumeChar(c);
			// reset the index
			index = 0u;
		}
		else if(c=='\r' && !index)
		{
				// consume the \n
				consumeChar(c);
				break;
		}
		else
		{
			line[index++] = c;
		}
	}

	if(header->transferCoding == HTTP_TRANSFER_CHUNKED)
	{
		// read the first chunk
		header->contentLengthOrChunk = 0;

		client->state = HTTP_READING_CHUNK_VALUE;
		readChunkLine(client);

	}
	else
		client->state = HTTP_READING_BODY;

	dbg("End of header\n");
	return HTTP_RETURN_OK;

}

// an async read of the chunk part, since in theory a chunk can be split in 2 packets
int readChunkLine(struct pico_http_client * client)
{
	char c = 0;

	if(client->header->contentLengthOrChunk==0 && client->state == HTTP_READING_BODY)
	{
		client->state = HTTP_READING_CHUNK_VALUE;
	}

	if(client->state == HTTP_READING_CHUNK_VALUE)
	{
		while(consumeChar(c)>0 && c!='\r' && c!=';')
		{
			if(is_hex_digit(c))
				client->header->contentLengthOrChunk = (client->header->contentLengthOrChunk << 4u) + hex_digit_to_dec(c);
			else
			{
				pico_err = PICO_ERR_EINVAL;
				// something went wrong
				return HTTP_RETURN_ERROR;
			}
		}

		if(c=='\r' || c==';') client->state = HTTP_READING_CHUNK_TRAIL;
	}

	if(client->state == HTTP_READING_CHUNK_TRAIL)
	{

		while(consumeChar(c)>0 && c!='\n');

		if(c=='\n') client->state = HTTP_READING_BODY;
	}

	return HTTP_RETURN_OK;
}
#endif
