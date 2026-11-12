#include <string.h>
struct E {};

int main(void) {
  char buf[8];
  memset(buf, 0x5a, sizeof buf);
  struct E (*p)[2] = (struct E (*)[2])buf;
  struct E e[2];
  memcpy(e, *p, sizeof e);
  struct { struct E z[2]; int x; } s = *(__typeof__(s) *)buf;
  __CPROVER_assert(s.x == 0x5a5a5a5a, "copied");
  return 0;
}
