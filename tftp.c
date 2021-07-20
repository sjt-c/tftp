/*

tftp - common code between server and client

*/

#if (0)
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#endif

#include "tftp.h"

char server_port_default[] = SERVER_PORT;

char *tftp_opcode_name[] =
{
	"UNDEFINED",
	"RRQ",
	"WRQ",
	"DATA",
	"ACK",
	"ERROR",
	"OACK"						/* RFC 2347 Addition */
};

char *tftp_error_string[] =
{
	"Not defined, see error message (if any).",	/* ErrorCode Value = 0 */
	"File not found.",							/* ErrorCode Value = 1 */
	"Access violation.",						/* ErrorCode Value = 2 */
	"Disk full or allocation exceeded.",		/* ErrorCode Value = 3 */
	"Illegal TFTP operation.",					/* ErrorCode Value = 4 */
	"Unknown transfer ID.",						/* ErrorCode Value = 5 */
	"File already exists.",						/* ErrorCode Value = 6 */
	"No such user.",							/* ErrorCode Value = 7 */
	"Terminate transfer."						/* ErrorCode Value = 8 */ /* RFC 2347 Addition */
};
