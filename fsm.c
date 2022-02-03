//
// Created by BillHidden on 1/27/2022.
//
#include <winsock2.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "fsm.h"
//
// Created by BillHidden on 1/25/2022.
//

#include <string.h>

typedef enum {
    LDX_SUCCESS = 1,
    STRIP_UPDATE_STATUS_MESSAGE_en,
} interconnect_message_enums;

static uint32_t message_lock = 0;

// this max size is based on the maximum message (struct) that is defined either in FBL or HF.
#define MAX_MESSAGE_PAYLOAD 4800

static message_t send_message_storage;

static SOCKET fbl_socket = INVALID_SOCKET;
static message_t receive_message;

typedef enum State {
    READ_MSG_ID, READ_MSG_SIZE, READ_MSG_PAYLOAD, MESSAGE_ERROR
} State;

#define MESSAGE_PROCESSED_OK 1

void reset_msg_input_state(const uint8_t *ptr, State *state, size_t *bytes_to_read) {
    ptr = (uint8_t *) &(receive_message.header.id);
    *state = READ_MSG_ID;
    receive_message.header.id = 0;
    receive_message.header.size = 0;
    *bytes_to_read = sizeof(receive_message.header.id);
}

void receive_input(void) {
    State state = READ_MSG_ID;
    uint8_t *ptr = 0;
    uint32_t bytes_to_read = sizeof(receive_message.header.id);
    int bytes_read;
    int continue_receiving = 1;

    reset_msg_input_state(ptr, &state, &bytes_to_read);

    while (continue_receiving) {
        bytes_read = bsd_receive(fbl_socket, ptr, bytes_to_read);

        if (bytes_read >= 0 && bytes_read < bytes_to_read) {
            bytes_to_read -= bytes_read;
            ptr += bytes_read;
        } else if (bytes_read == bytes_to_read) {
            switch (state) {
                case READ_MSG_ID:
                    // is this a known message id? if not continue looking for a known message id.
                    if (valid_msg_id(receive_message.header.id)) {
                        state = READ_MSG_SIZE;
                        bytes_to_read = sizeof(receive_message.header.size);
                        ptr = (uint8_t *) &(receive_message.header.size);
                    } else {
                        reset_msg_input_state(ptr, &state, &bytes_to_read);
                        // log error
                    }
                    break;

                case READ_MSG_SIZE:
                    // is this a good size given a known message id? if not go back to reading a message id.
                    if (valid_msg_size(receive_message.header.id, receive_message.header.size)) {
                        state = READ_MSG_PAYLOAD;
                        bytes_to_read = receive_message.header.size;
                        ptr = (uint8_t *) &(receive_message.payload);
                    } else {
                        reset_msg_input_state(ptr, &state, &bytes_to_read);
                        // log error
                    }
                    break;

                case READ_MSG_PAYLOAD:
                    // have we successfully processed the received message?
                    if (MESSAGE_PROCESSED_OK != process_message(&receive_message)) {
                        // log error
                    }
                    // zero of the payload and start receiving another message
                    memset(&receive_message.payload, 0, sizeof(receive_message.payload));
                    reset_msg_input_state(ptr, &state, &bytes_to_read);

                    break;

                default:
                    // log error
                    memset(&receive_message.payload, 0, sizeof(receive_message.payload));
                    reset_msg_input_state(ptr, &state, &bytes_to_read);
            }
        }
            // continue receiving bytes.
        else {
            // log errno.
            // close fbl_socket
            continue_receiving = 0;
        }
    }
}

int bsd_receive(SOCKET a_socket, void *ptr, size_t size) {
    a_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    recv(a_socket, ptr, (int) size, MSG_WAITALL);
    return 0;
}

typedef struct {
    uint32_t id;
    size_t size;
} valid_msg_t;

typedef enum {
    ReadMsgId_st,
    ReadMsgSize_st,
    ReadMsgPayload_st,
    MsgIdError_st,
    MsgTimeout_st,
    CloseMsg_st,
    MsgSizeError_st,
    ProcessMsg_st,
    MsgPayloadError_st,
    MsgReadError_st,
    last_State,
} FSMState;

typedef enum {
    accept_evt,
    more_data_evt,
    valid_id_evt,
    timeout_evt,
    invalid_id_evt,
    socket_closed_evt,
    socket_error_evt,
    valid_msg_evt,
    valid_size_evt,
    msg_processed_evt,
    last_event,
} FSMEvent;

typedef FSMState (*eventHandler)(void);

FSMState default_action_fn(void) {
    return ReadMsgId_st;
}

typedef struct {
  FSMState state;
  FSMEvent event;
  eventHandler action;
} StateElement;

static StateElement StateMachine[] =
        {
                {ReadMsgId_st, more_data_evt, default_action_fn},
        };


int fsm_runner(void) {
    FSMState nextState = Read_Msg_Id_State;
    FSMEvent newEvent;
    int running = 1;
    while(running == 1) {
        newEvent = NextEvent();
        if (( nextState < last_State) && (newEvent < last_event) && StateMachine[nextState][newEvent] != NULL)
        {
            nextState = (*StateMachine[nextState][newEvent])();
        }
        else {
            // stop StateMachine invalid state/event tuple
            running = 0;
        }
    }
    return 0;
}