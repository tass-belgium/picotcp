/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_zmtp.h"
#include "pico_socket.h"
#include "pico_zmq.h"



struct zmtp_socket {
    struct pico_socket *sock;
    enum zmq_state state;
    zmq_socket parent;
    enum zmq_socket_type role;
    uint16_t bytes_received;
};
