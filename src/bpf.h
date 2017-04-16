

#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

struct insn {
  uint16_t  code; /* Operation Code of BPF */
  uint8_t   jt;   /* Jump If True          */
  uint8_t   jf;   /* Jump If False         */
  uint32_t  k;    /* Extra datas           */

  void print() const
  {
    printf("code: 0x%x\n", code);
    printf("jt  : 0x%x\n", jt  );
    printf("jf  : 0x%x\n", jf  );
    printf("k   : 0x%x\n", k   );
  }
};




