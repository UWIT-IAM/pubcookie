/* BASE64 encoding stuff. */

#define NL 99   /* invalid character */
#define EQ 98   /* equal sign has special meaning. */

static unsigned char encode[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 
  'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', 
  '8', '9', '+', '/'};

static unsigned char decode[256] = { 
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, 62, NL, NL, NL, 63, 52, 53,
  54, 55, 56, 57, 58, 59, 60, 61, NL, NL, 
  NL, EQ, NL, NL, NL,  0,  1,  2,  3,  4, 
  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, NL, NL, NL, NL, NL, NL, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
  39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, NL, NL, NL, NL, NL, NL, NL, 
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
  NL, NL, NL, NL, NL, NL};

int base64_encode(unsigned char *in, unsigned char *out, int size) {
  unsigned int a, b, c;

  while(size > 0) {
    a = (unsigned int) *in++;
    size--;
    if(size > 0) {
      b = (unsigned int) *in++;
      size--;
      if(size > 0) {
	c = (unsigned int) *in++;
	size--;
	*out++ = encode[(a>>2)];
	*out++ = encode[((a&3)<<4)+(b>>4)];
	*out++ = encode[((b&15)<<2)+(c>>6)];
	*out++ = encode[((c&63))];
      } else {
	*out++ = encode[(a>>2)];
	*out++ = encode[((a&3)<<4)+(b>>4)];
	*out++ = encode[((b&15)<<2)];
	*out++ = '=';
      }
    } else {
      *out++ = encode[(a>>2)];
      *out++ = encode[((a&3)<<4)];
      *out++ = '=';
      *out++ = '=';
    }
  }
  *out = 0;
  return 1;
}

int base64_decode(unsigned char *in, unsigned char *out) {
  unsigned int a, b, c, d;
  int size = strlen(in);
  int correct = 0;

  while(size > 0) {
    if(*in != 0) {
      a = decode[(unsigned int) *in++];
      if(a == EQ)
	return 0;
      size--;
      if(*in != 0) {
	b = decode[(unsigned int) *in++];
	if(b == EQ)
	  return 0;
	size--;
	if(*in != 0) {
	  c = decode[(unsigned int) *in++];
	  if(c == EQ) correct++;
	  size--;
	  if(*in != 0) {
	    d = decode[(unsigned int) *in++];
	    if(d == EQ) correct++;
	    size--;
	    if((a == NL) || (b == NL) || (c == NL) || (d == NL))
	      return 0;
	    *out++ = (a << 2) + (b >> 4);
	    *out++ = ((b & 15) << 4) + (c >> 2);
	    *out++ = ((c & 3) << 6) + d;
	  } else
	    return 0;
	} else
	  return 0;
      } else
	return 0;
    } else
      return 0;
  }
  *(out-correct) = 0;
  return 1;
}
