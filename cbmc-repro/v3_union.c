#include <string.h>
struct E {};
struct W { struct E z[2]; char pad[8]; };
union U { char bytes[8]; struct W w; };

int main(void) {
  union U src, dst;
  memset(&src, 0x5a, sizeof src);
  dst = *(union U *)(void *)&src;
  __CPROVER_assert(dst.bytes[0] == 0x5a, "copied");
  return 0;
}
