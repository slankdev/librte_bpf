
#include <stdio.h>
#include <stdlib.h>
#define XBYAK_NO_OP_NAMES
#include <xbyak/xbyak.h>
#include <slankdev/hexdump.h>
#include <slankdev/packet.h>

class Sample : public Xbyak::CodeGenerator {
	void operator=(const Sample&);
public:


	Sample(void *userPtr = 0, size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE)
    : Xbyak::CodeGenerator(size, userPtr)
	{
    /*
     * MEMO
     *  edi     1st arg
     *  esi     2nd arg
     *  eax     ret value
     *
     * MNEMONIC
     *  mov(a, b)    a <- b
     *  add(a, b)    a <- a+b
     *  test(a, b)
     *
     * FUNC
     *  void filter(const uint8_t* ptr, size_t len);
     */

		mov(ecx, edi);
    add(ecx, 12);
    cmp(byte[ecx+0], 0x08);
    jnz("FIN");
    // add(ecx, 1);
    // cmp(dword[ecx], 0x06);
    // jnz("FIN");

    mov(eax, 1);
		ret();

  L("FIN");
    mov(eax, 0);
    ret();
	}
};



int main()
{
		Sample s;
		printf("Xbyak version=%s\n", s.getVersionString());

		int (*func)(const void*,size_t) = s.getCode<int (*)(const void*,size_t)>();

    const void* p = slankdev::raw_arp_pack();
    slankdev::hexdump(stdout, p, 42);

    printf("result: %d\n", func(p,42));
}

