/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .
 *********************************************************************/
#ifndef PICO_TFTP_H
#define PICO_TFTP_H

#include <stdint.h>
#include <stddef.h>

#define PICO_TFTP_PORT          (69)
#define PICO_TFTP_PAYLOAD_SIZE  (512)

#define PICO_TFTP_NONE  0
#define PICO_TFTP_RRQ   1
#define PICO_TFTP_WRQ   2
#define PICO_TFTP_DATA  3
#define PICO_TFTP_ACK   4
#define PICO_TFTP_ERROR 5
#define PICO_TFTP_OACK  6

/* Callback user events */
#define PICO_TFTP_EV_OK    0
#define PICO_TFTP_EV_OPT   1
#define PICO_TFTP_EV_ERR_PEER  2
#define PICO_TFTP_EV_ERR_LOCAL 3

/* TFTP ERROR CODES */
#define TFTP_ERR_UNDEF     0
#define TFTP_ERR_ENOENT    1
#define TFTP_ERR_EACC      2
#define TFTP_ERR_EXCEEDED  3
#define TFTP_ERR_EILL      4
#define TFTP_ERR_ETID      5
#define TFTP_ERR_EEXIST    6
#define TFTP_ERR_EUSR      7
#define TFTP_ERR_EOPT      8

/* Session options */
#define PICO_TFTP_OPTION_FILE 1

/* timeout: 0 -> adaptative, 1-255 -> fixed */
#define PICO_TFTP_OPTION_TIME 2


#define PICO_TFTP_MAX_TIMEOUT 255
#define PICO_TFTP_MAX_FILESIZE (65535 * 512 - 1)

struct pico_tftp_session;

struct pico_tftp_session *pico_tftp_session_setup(union pico_address *a, uint16_t family);
int pico_tftp_set_option(struct pico_tftp_session *session, uint8_t type, int32_t value);
int pico_tftp_get_option(struct pico_tftp_session *session, uint8_t type, int32_t *value);

int pico_tftp_start_rx(struct pico_tftp_session *session, uint16_t port, const char *filename,
                       int (*user_cb)(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg), void *arg);
int pico_tftp_start_tx(struct pico_tftp_session *session, uint16_t port, const char *filename,
                       int (*user_cb)(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg), void *arg);

int pico_tftp_reject_request(union pico_address *addr, uint16_t port, uint16_t error_code, const char *error_message);
int32_t pico_tftp_send(struct pico_tftp_session *session, const uint8_t *data, int32_t len);

int pico_tftp_listen(uint16_t family, void (*cb)(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename, int32_t len));

int pico_tftp_parse_request_args(char *args, int32_t len, int *options, uint8_t *timeout, int32_t *filesize);

int pico_tftp_abort(struct pico_tftp_session *session, uint16_t error, const char *reason);
int pico_tftp_close_server(void);

int pico_tftp_get_file_size(struct pico_tftp_session *session, int32_t *file_size);

/* SPECIFIC APPLICATION DRIVEN FUNCTIONS */
struct pico_tftp_session *pico_tftp_app_setup(union pico_address *a, uint16_t port, uint16_t family, int *synchro);

int pico_tftp_app_start_rx(struct pico_tftp_session *session, const char *filename);
int pico_tftp_app_start_tx(struct pico_tftp_session *session, const char *filename);

int32_t pico_tftp_get(struct pico_tftp_session *session, uint8_t *data, int32_t len);
int32_t pico_tftp_put(struct pico_tftp_session *session, uint8_t *data, int32_t len);

#endif
