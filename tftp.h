/*

tftp - common code between server and client

*/

#ifndef __TFTP_H__
#define __TFTP_H__

/*
Type   Op #     Format without header

RFC 783
       2 bytes    string   1 byte     string   1 byte
       -----------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
WRQ    -----------------------------------------------

RFC 2347 Extension
       2 bytes    string   1 byte     string   1 byte      string   1 byte     string   1 byte     string   1 byte     string   1 byte
       --------------------------------------------------------------------------------------------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |   Option 1  |   0  |   Value 1  |   0  |  Option n  |   0  |   Value n  |   0  |
WRQ    --------------------------------------------------------------------------------------------------------------------------------

       2 bytes    2 bytes       n bytes
       ---------------------------------
DATA  | 03    |   Block #  |    Data    |
       ---------------------------------

       2 bytes    2 bytes
       -------------------
ACK   | 04    |   Block #  |
       --------------------

       2 bytes  2 bytes        string    1 byte
       ----------------------------------------
ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
       ----------------------------------------

RFC 2347 Addition
       2 bytes    string   1 byte     string   1 byte     string   1 byte     string   1 byte
       ---------------------------------------------------------------------------------------
OACK  | 06    |  Option 1  |   0  |   Value 1  |   0  |  Option n  |   0  |   Value n  |   0  |
       ---------------------------------------------------------------------------------------

*/

#include <stdbool.h>

#ifndef SERVER_PORT
	#define SERVER_PORT				"69"
#endif

#define TIMEOUT_SEC(S)				((S) * 1000)
#define TIMEOUT_uSEC(U)				((U))
#define TIMEOUT(S, U)				(TIMEOUT_SEC(S) + TIMEOUT_uSEC(U))

#define TFTP_UNDEFINED				0
#define TFTP_RRQ					1
#define TFTP_WRQ					2
#define TFTP_DATA					3
#define TFTP_ACK					4
#define TFTP_ERROR					5
#define TFTP_OACK					6

/* These are the lengths of valid values for the "mode" field. */
#define TFTP_MODE_OCTET				5	/* "octet" */
#define TFTP_MODE_NETASCII			8	/* "netascii" */
#define TFTP_MODE_MAIL				4	/* "mail" */
#define TFTP_MODE_LEN				TFTP_MODE_NETASCII

/* The maximum length for a requested filename. 255 should be reasonably large enough. */
#define TFTP_FILENAME_LEN			255

#define TFTP_OP_RRQ					TFTP_RRQ
#define TFTP_OP_WRQ					TFTP_WRQ
#define TFTP_OP_DATA				TFTP_DATA
#define TFTP_OP_ACK					TFTP_ACK
#define TFTP_OP_ERROR				TFTP_ERROR
#define TFTP_OP_OACK				TFTP_OACK		/* RFC 2347 Addition */

#define TFTP_OP_FIRST				TFTP_OP_RRQ
#define TFTP_OP_LAST				TFTP_OP_ERROR

#define TFTP_ERR_UNDEFINED			0
#define TFTP_ERR_FILE_NOT_FOUND		1
#define TFTP_ERR_ACCESS_VIOLATION	2
#define TFTP_ERR_DISK_FULL			3
#define TFTP_ERR_ILLEGAL_OP			4
#define TFTP_ERR_UNKNOWN_TID		5
#define TFTP_ERR_FILE_EXISTS		6
#define TFTP_ERR_UNKNOWN_USER		7
#define TFTP_ERR_TERMINATE			8

#define recv_errorcode				recv_block
#define recv_errmsg					recv_mode

#ifndef __bool_true_false_are_defined
typedef enum { false, true } bool;
#endif

extern char server_port_default[], *tftp_opcode_name[], *tftp_error_string[];

#endif /* !__TFTP_H__ */
