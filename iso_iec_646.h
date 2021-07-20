#ifndef __ISO_IEC_646_H__
#define __ISO_IEC_646_H__

#include <byte.h>

#define __ascii(I, M)	(iso_iec_646_abbr[((I)&(M))])

#define __ascii7(I)		__ascii((I), (0X7F))

/* these print the full value of a byte with the lower 128 as 7-bit ascii, the higher 128
in the format specified */
#define __ascii7_dec(I)	(((I)&(0XFF))<128?__ascii7((I)):(__byte_dec((I))))
#define __ascii7_oct(I)	(((I)&(0XFF))<128?__ascii7((I)):(__byte_oct((I))))
#define __ascii7_hex(I)	(((I)&(0XFF))<128?__ascii7((I)):(__byte_hex((I))))

#define __dec(I)		(((I)&(0XFF))>31&&((I)&(0XFF))<128?__ascii7((I)):(__byte_dec((I))))
#define __oct(I)		(((I)&(0XFF))>31&&((I)&(0XFF))<128?__ascii7((I)):(__byte_oct((I))))
#define __hex(I)		(((I)&(0XFF))>31&&((I)&(0XFF))<128?__ascii7((I)):(__byte_hex((I))))

extern char *iso_iec_646_abbr[];

#endif /* !__ISO_IEC_646_H__ */
