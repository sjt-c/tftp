#ifndef __BYTE_H__
#define __BYTE_H__

#define __byte_dec(I)	(byte_dec[((I) & (0XFF))])
#define __byte_oct(I)	(byte_oct[((I) & (0XFF))])
#define __byte_hex(I)	(byte_hex[((I) & (0XFF))])

extern char *byte_dec[];
extern char *byte_oct[];
extern char *byte_hex[];

#endif /* __BYTE_H__ */
