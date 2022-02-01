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

#pragma pack(1)
typedef struct strip_update_status_tag {
    uint32_t sequence_no;
    uint32_t param_1;
    uint32_t param_2;
} strip_update_status_t;
#pragma pack()

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
    uint32_t bytes_to_read = 0;
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

valid_msg_t KNOWN_MESSAGE_IDS[] = {{.id = 1, .size = 10},
                                   {.id = 2, .size = 20},
                                   {.id = 3, .size = 30},
                                   {.id = 4, .size = 40},
                                   {.id = 5, .size = 50},
                                   {.id = 6, .size = 60},
                                   {.id = 7, .size = 70},
                                   {.id = 100, .size = 7000},
};

int valid_msg_id(uint32_t id) {
    int found = 0;
    for (int i = 0; i < sizeof(KNOWN_MESSAGE_IDS); i++) {
        if (id == KNOWN_MESSAGE_IDS[i].id) {
            found = 1;
            break;
        }
    }
    return found;
}

int valid_msg_size(uint32_t id, size_t size) {
    int is_valid = 0;
    for (int i = 0; i < sizeof(KNOWN_MESSAGE_IDS); i++) {
        if (id == KNOWN_MESSAGE_IDS[i].id) {
            is_valid = KNOWN_MESSAGE_IDS[i].size == size;
            break;
        }
    }
    return is_valid;
}

int process_message(message_t *message) {
    return sizeof(*message);
}
typedef enum {
    Idle_Msg_State,
    Read_Msg_Id_State,
    Read_Msg_Size_State,
    Read_Msg_Payload_State,
    Bad_Msg_State,
    Read_very_long_Payload_State,
    last_State,
} FSMState;

typedef enum {
    Start_Msg_Event,
    Validate_Msg_Id_Event,
    Validate_Msg_Size_Event,
    Process_Msg_Event,
    Bad_Msg_Event,
    Process_VeryLong_Msg_Event,
    last_event,
} FSMEvent;

FSMEvent NextEvent() {
    return Start_Msg_Event;
}

typedef FSMState (*const afEventHandler[last_State][last_event])(void);
typedef FSMState (*eventHandler)(void);

FSMState ReadMsgId(void) {
    return Read_Msg_Size_State;
}

FSMState ValidateMsgSize(void) {
    return Read_Msg_Size_State;
}

FSMState ReadMsgSize(void) {
    return Read_Msg_Payload_State;
}

FSMState ProcessMessage(void) {
    static int tries = 0;
    tries++;
    if (tries > 5) {
        return Bad_Msg_State;
    }

    return Idle_Msg_State;
}

FSMState HandleBadMsg(void) {
    return Idle_Msg_State;
}

FSMState ProcessVeryLongMessage(void) {
    return Idle_Msg_State;
}

static const afEventHandler StateMachine =
        {
                [Idle_Msg_State] = {[Start_Msg_Event] = ReadMsgId},
                [Read_Msg_Id_State] = {[Validate_Msg_Id_Event] = ValidateMsgSize},
                [Read_Msg_Size_State] = {[Validate_Msg_Size_Event] = ReadMsgSize},
                [Read_Msg_Payload_State] = {[Process_Msg_Event] = ProcessMessage},
                [Bad_Msg_State] = {[Bad_Msg_Event] = HandleBadMsg},
                [Read_very_long_Payload_State] = {[Process_VeryLong_Msg_Event] = ProcessVeryLongMessage},

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