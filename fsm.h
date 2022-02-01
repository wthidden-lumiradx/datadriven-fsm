//
// Created by BillHidden on 1/27/2022.
//
#ifndef DATADRIVEN_FSM_FSM_H

typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;

#pragma pack(1)
typedef struct
{
    uint32_t id;
    size_t size;
} msg_header_t;
typedef struct
{
    uint8_t payload[MAX_MESSAGE_PAYLOAD];
} msg_payload_t;

typedef struct
{
    msg_header_t  header;
    msg_payload_t payload;
} message_t;
#pragma pack()

int bsd_receive(SOCKET socket, void* ptr, size_t size);
int valid_msg_id(uint32_t id);
int valid_msg_size(uint32_t id, uint32_t size);
int process_message(message_t* message);


#define DATADRIVEN_FSM_FSM_H

#endif //DATADRIVEN_FSM_FSM_H
