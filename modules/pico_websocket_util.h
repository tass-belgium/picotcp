#ifndef PICO_WEBSOCKET_UTIL_H
#define PICO_WEBSOCKET_UTIL_H


/* FIN bit -- ==1 if this is the last frame in a message */
#define WS_FIN_ENABLE         1
#define WS_FIN_DISABLE        0

/* RSV1, RSV2, RSV3 -- these are one bit each
 * Must be 0 unless an extension is negotiated that defines meanings for non-zero values.
 * If a nonzero value is received and none of the negotiated extensions defines the meanings
 * of such a nonzero value, the receiving endpoint MUST fail the websocket connection
*/

/* List of opcodes - defines operation of the payload data */

#define WS_CONTINUATION_FRAME 0
#define WS_TEXT_FRAME         1
#define WS_BINARY_FRAME       2
#define WS_CONN_CLOSE         8
#define WS_PING               9
#define WS_PONG               10

/* Masking - client has to mask data sent to server */
#define WS_MASK_ENABLE        1
#define WS_MASK_DISABLE       0


/* List of events - shared between client and server */
#define EV_WS_ERR             1u
#define EV_WS_BODY            64u

#endif /* PICO_WEBSOCKET_UTIL_H */
