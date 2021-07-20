#include <errno.h>
#include <stdlib.h>
#include <limits.h>

/*
Parse a string and attempt to convert it to a long int
Arguments:
	char *str : string to parse
	long *val : the parse value
Return Values:
	0 : parsing failed, the value in val is unchanged
	1 : parsing succeeded, the value in val is changed
*/
int parse_long(const char *str, long *val)
{
	int base = 0;
	char *end_ptr = NULL;
	long _val = 0;

	errno = 0;
	_val = strtol(str, &end_ptr, base);
	
	if (str == end_ptr)
		return 0;
	
	if (errno == ERANGE)
		return 0;
	
	if (*end_ptr)
		return 0;
	
	*val = _val;

	return 1;
}
