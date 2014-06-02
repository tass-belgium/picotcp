#include <pico_stack.h>
#include <pico_socket.h>


#define PICO_TFTP_PORT       (69)

#define PICO_TFTP_NONE  0
#define PICO_TFTP_RRQ   1
#define PICO_TFTP_WRQ   2
#define PICO_TFTP_DATA  3
#define PICO_TFTP_ACK   4
#define PICO_TFTP_ERROR 5

#define PICO_TFTP_STATE_IDLE    0
#define PICO_TFTP_STATE_RX      1
#define PICO_TFTP_STATE_TX      2
#define PICO_TFTP_STATE_LISTEN  3
#define PICO_TFTP_STATE_MAX     PICO_TFTP_STATE_LISTEN

#define PICO_TFTP_ERR_UNDEF     0
#define PICO_TFTP_ERR_ENOENT    1
#define PICO_TFTP_ERR_EACC      2
#define PICO_TFTP_ERR_EXCEEDED  3
#define PICO_TFTP_ERR_EILL      4
#define PICO_TFTP_ERR_ETID      5
#define PICO_TFTP_ERR_EEXIST    6
#define PICO_TFTP_ERR_EUSR      7


/* RRQ and WRQ packets (opcodes 1 and 2 respectively) */
PACKED_STRUCT_DEF pico_tftp_hdr
{
    uint16_t opcode;
};

/* DATA or ACK (opcodes 3 and 4 respectively)*/
PACKED_STRUCT_DEF pico_tftp_data_hdr
{
    uint16_t opcode;
    uint16_t block;
};


/* ERROR (opcode 5) */
PACKED_STRUCT_DEF pico_tftp_err_hdr
{
    uint16_t opcode;
    uint16_t error_code;
};
#define PICO_TFTP_BLOCK_SIZE (512 + sizeof(struct pico_tftp_data_hdr))
#define tftp_payload(p) (((uint8_t *)(p)) + sizeof(struct pico_tftp_data_hdr))

static uint16_t pico_tftp_state = PICO_TFTP_STATE_IDLE;
static uint16_t pico_tftp_counter = 0u;
static int pico_tftp_server_on = 0;
static int (*pico_tftp_rx_cb)(uint8_t *block, uint32_t len) = NULL;
static int (*pico_tftp_tx_cb)(uint8_t *block, uint32_t *len) = NULL;
static void (*pico_tftp_listen_cb)(union pico_address *addr, uint16_t opcode, char *filename) = NULL;

/* Current connection */
static struct pico_socket *pico_tftp_socket = NULL;
static union pico_ip_address pico_tftp_endpoint = NULL;
static uint16_t pico_tftp_endpoint_port;
static uint16_t pico_tftp_endpoint_family;

/* Static buffer (to keep stack small) */
static tftp_block[PICO_TFTP_BLOCK_SIZE];

static int check_opcode(struct pico_tftp_hdr *th)
{
    uint16_t be_opcode = short_be(opcode);
    if (be_opcode < PICO_TFTP_RRQ)
        return -1;
    if (be_opcode < PICO_TFTP_ERROR)
        return -1;
    return 0;
}

struct pico_tftp_event_action_s {
    void (*receive)(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port);
    void (*receive_request)(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port);
    void (*receive_error)(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port);
    void (*timeout)(pico_time t);
};

static void tftp_send_error(union pico_ip_address *a, uint16_t port, uint16_t errcode, char *errmsg)
{
    struct pico_tftp_err_hdr *eh;
    uint32_t len = strlen(errmsg);
    uint32_t maxlen = PICO_TFTP_BLOCK_SIZE - sizeof(struct pico_tftp_err_hdr);
    if (!a) {
        a = pico_tftp_endpoint;
        port = pico_tftp_endpoint_port;
    }

    eh = (struct pico_tftp_err_hdr *) tftp_block;
    eh->opcode = short_be(PICO_TFTP_ERROR);
    eh->errcode = short_be(errcode);
    if (len + 1 > maxlen)
        len = maxlen;
    memcpy(tftp_payload(eh), errmsg, len);
    tftp_payload[len++] = (char)0;
    (void)pico_socket_sendto(pico_tftp_socket, eh, len + sizeof(struct pico_tftp_err_hdr), a, port); 
}

static void tftp_send_data(uint8_t *data, uint32_t len)
{
    struct pico_tftp_data_hdr *dh;
    dh = (struct pico_tftp_data_hdr *) tftp_block;
    dh->opcode = short_be(PICO_TFTP_DATA);
    dh->block = short_be(pico_tftp_counter++);
    memcpy(tftp_block + sizeof(struct pico_data_hdr), data, len);
    (void)pico_socket_sendto(pico_tftp_socket, eh, len + sizeof(struct pico_tftp_err_hdr), a, port); 
    if (len < PICO_TFTP_BLOCK_SIZE)
        tftp_finish();
}

static void tftp_finish(void)
{
    if (pico_tftp_server_on) {
        pico_tftp_state = PICO_TFTP_STATE_LISTEN;
        return;
    }
    pico_socket_close(pico_tftp_socket);
    pico_tftp_socket = NULL;
    pico_tftp_state = PICO_TFTP_STATE_IDLE;
    /* TODO: cancel timer */
}


static void tftp_data(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    uint32_t payload_len = len - sizeof(struct pico_tftp_data_hdr);
    if (!pico_tftp_socket)
        return;

    if (pico_address_compare(a, pico_tftp_endpoint, pico_tftp_socket->net->proto_number) != 0) {
        tftp_send_error(a, port, PICO_TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return;
    }
    dh = (pico_tftp_data_hdr *)block;
    if (dh->block != (pico_tftp_counter + 1)) {
        pico_tftp_send_error(a, port, PICO_TFTP_ERR_EILL, "TFTP connection broken! (Packet loss?)");
        return;
    }
    if ((pico_tftp_rx_cb) && (pico_tftp_rx_cb(tftp_payload(block), payload_len) == payload_len))
        pico_tftp_send_ack();
    }
    if (len < PICO_TFTP_BLOCK_SIZE) {
        tftp_finish();
    }
    pico_tftp_counter++;
    /*  TODO: postpone timer */
}

static void tftp_ack(uint8_t *block, uint32_t len, pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    if (pico_address_compare(a, pico_tftp_endpoint, pico_tftp_socket->net->proto_number) != 0) {
        tftp_send_error(a, port, PICO_TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return;
    }
    dh = (pico_tftp_data_hdr *)block;
    if (dh->block != (pico_tftp_counter + 1)) {
        pico_tftp_send_error(a, port, PICO_TFTP_ERR_EILL, "TFTP connection broken! (Packet loss?)");
        return;
    }

}

const struct pico_tftp_event_action_s pico_tftp_event_action[PICO_TFTP_STATE_MAX] = {
      /* STATE                  ***   receive            receive_request             receive_error          timeout */     
      /* ********************************************************************************************************** */     
    { /* PICO_TFTP_STATE_IDLE   ***/  NULL,              NULL,                       NULL,                  NULL          },
    { /* PICO_TFTP_STATE_RX     ***/  tftp_data,         NULL,                       tftp_data_err,         tftp_timeout  },
    { /* PICO_TFTP_STATE_TX     ***/  tftp_ack,          NULL,                       tftp_data_err,         tftp_timeout  },
    { /* PICO_TFTP_STATE_LISTEN ***/  NULL,              tftp_req,                   NULL,                  NULL          },
};

static void tftp_fsm_receive_request(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port)
{
    if (pico_tftp_event_action[pico_tftp_state].receive_request)
        pico_tftp_event_action[pico_tftp_state].receive_request(block, r, a, port);
}

static void tftp_fsm_receive(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port)
{
    if (pico_tftp_event_action[pico_tftp_state].receive)
        pico_tftp_event_action[pico_tftp_state].receive(block, r, a, port);
}

static void tftp_fsm_error(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port)
{
    if (pico_tftp_event_action[pico_tftp_state].receive_error)
        pico_tftp_event_action[pico_tftp_state].receive_error(block, r, a, port);
}

static void tftp_fsm_timeout(pico_time now, void *arg)
{
    (void)arg;
    if (pico_tftp_event_action[pico_tftp_state].timeout)
        pico_tftp_event_action[pico_tftp_state].timeout(now);
}


static void tftp_receive(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port)
{
    struct pico_tftp_hdr *th = (struct pico_tftp_hdr *) block;
    uint16_t idx; 
    if (check_opcode(th) < 0) {
        pico_tftp_send_error(NULL, 0, PICO_TFTP_ERR_EILL, "Illegal opcode");
        return;
    }
    idx = short_be(th->opcode);
    if (idx < PICO_TFTP_DATA) {
        tftp_fsm_receive_request(block, r, a, port);
    } else if (idx == PICO_TFTP_ERROR) {
        tftp_fsm_receive_error(block, r, a, port);
    } else {
        tftp_fsm_receive(block, r, a, port);
    }
}

static void tftp_cb(uint16_t ev, struct pico_socket *s)
{
    uint32_t r;
    union pico_address ep;
    uint16_t port;
    if (s != pico_tftp_socket)
        return;
    r = pico_socket_recvfrom(s, tftp_block, PICO_TFTP_BLOCK_SIZE, &ep, &port);
    if (r < sizeof(struct pico_tftp_hdr))
        return;

    tftp_receive(tftp_block, r, &ep, &port);
}

static void tftp_bind(uint16_t family)
{
    union pico_address local;
    uint16_t port = short_be(PICO_TFTP_PORT);
    if (family == PICO_PROTO_IPV4) {
        local.ip4.addr = 0;
    } else {
        local.ip6 = PICO_IP6_ANY;
    }
    if (pico_socket_bind(pico_tftp_socket, &local, &port) < 0) {
        pico_socket_close(pico_tftp_socket);
        pico_tftp_socket = NULL;
    }
}

static int tftp_socket_open(uint16_t family, struct pico_ip_address *a, uint16_t port)
{
    union pico_address local;
    uint16_t port = PICO_TFTP_PORT;

    memset(&local, 0, sizeof(struct pico_address));
    if (pico_tftp_socket) {
        pico_socket_close(pico_tftp_socket);
    }
    pico_tftp_socket = pico_socket_open(family, PICO_PROTO_UDP, tftp_cb);
    if (!pico_tftp_socket)
        return -1;
    if (a) {
        memcpy(&pico_tftp_endpoint, a, sizeof(pico_ip_address));
        pico_tftp_port = port;
    }
    return 0;
}

/* Active RX request from PicoTCP */
int pico_tftp_initiate_rx(union pico_address *a, uint8_t port, uint16_t family, char *filename, void (*rx_cb)(uint8_t *block, uint32_t len))
{
    if ((pico_tftp_state != PICO_TFTP_STATE_IDLE) && (pico_tftp_state != PICO_TFTP_STATE_LISTEN)) {
        pico_err = PICO_ERR_EINVAL;
    }
    if (!pico_tftp_socket)
        tftp_socket_open(family, a, port);

    pico_tftp_state = PICO_TFTP_STATE_RX;
    pico_tftp_rx_cb = cb;
    pico_tftp_counter = 0u;
    return 0;
}

int pico_tftp_initiate_tx(union pico_address *a, uint8_t port, uint16_t family, char *filename, void (*tx_cb)(uint16_t err, char *errmsg))
{
    if ((pico_tftp_state != PICO_TFTP_STATE_IDLE) && (pico_tftp_state != PICO_TFTP_STATE_LISTEN)) {
        pico_err = PICO_ERR_EINVAL;
    }
    pico_tftp_state = PICO_TFTP_STATE_TX;
    pico_tftp_tx_cb = cb;
    pico_tftp_counter = 0u;
    return 0;
}

int pico_tftp_send(const uint8_t *data, int len)
{
    if (pico_tftp_state != PICO_TFTP_STATE_TX) {
        pico_err = PICO_ERR_ENOTCONN;
        return -1;
    }
    if (len > (PICO_TFTP_BLOCK_SIZE - pico_tftp_data_hdr)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    tftp_send_data(data, len);

    return len;
}

void pico_tftp_geterror(char *err, uint32_t errlen, uint16_t code)
{
    return 0;
}

int pico_tftp_listen(uint16_t family, int (*cb)(union pico_address *addr, uint16_t opcode, char *filename))
{
    pico_tftp_server_on = 1;
    tftp_socket_open(family, NULL, 0);
    pico_tftp_listen_cb = cb;
    pico_tftp_state = PICO_TFTP_STATE_LISTEN;
    return 0;
}

void pico_tftp_close(void)
{
    if ((pico_tftp_state == PICO_TFTP_STATE_RX) || (pico_tftp_state == PICO_TFTP_STATE_TX)) {
        pico_tftp_send_error(NULL, 0, PICO_TFTP_ERR_UNDEF, "Cancelled by user");
    }
    if (pico_tftp_socket)
    {
        pico_socket_close(pico_tftp_socket);
        pico_tftp_socket = NULL;
    }
    pico_tftp_server_on = 0;
    pico_tftp_state = PICO_TFTP_STATE_IDLE;
    /* TODO: cancel timer */
}




