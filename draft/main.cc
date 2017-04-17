

/*
 * MEMO
 *  edi     1st arg
 *  esi     2nd arg
 *  eax     ret value
 *
 *  ecx     free as A Acumulator
 *  edx     free as X Index Register
 *
 * MNEMONIC
 *  mov(a, b)    a <- b
 *  add(a, b)    a <- a+b
 *  test(a, b)
 *
 * FUNC
 *  void filter(const uint8_t* ptr, size_t len);
 */



#include <slankdev/hexdump.h>
#include <slankdev/packet.h>
#include <slankdev/endian.h>
#include <slankdev/extra/bpf.h>
#include <slankdev/extra/pcap.h>
#include <slankdev/extra/capstone.h>
#define XBYAK_NO_OP_NAMES
#include <xbyak/xbyak.h>



uint8_t raw_packet[] = {
    /* arp packet */
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01,
    // 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    // 0x00, 0x00,

    /* tcp packet */
    0x84, 0xdb, 0xac, 0x31, 0x1d, 0xfa, 0x80, 0xe6,
    0x50, 0x17, 0x18, 0x46, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x80, 0x91, 0xb3, 0x40, 0x00, 0x40, 0x06,
    0x3b, 0x57, 0xc0, 0xa8, 0x64, 0x67, 0xa3, 0x2c,
    0xa5, 0x31, 0x81, 0x42, 0x00, 0x50, 0x9b, 0x4c,
    0x6e, 0x59, 0x4a, 0x9e, 0x73, 0x7e, 0x80, 0x18,
    0x00, 0xe5, 0x54, 0xd9, 0x00, 0x00, 0x01, 0x01,
    0x08, 0x0a, 0x00, 0x18, 0x00, 0x16, 0x4e, 0xf8,
    0xcd, 0x22, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20,
    0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
    0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
    0x73, 0x6c, 0x61, 0x6e, 0x6b, 0x64, 0x65, 0x76,
    0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a, 0x55, 0x73,
    0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74,
    0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37,
    0x2e, 0x35, 0x30, 0x2e, 0x33, 0x0d, 0x0a, 0x41,
    0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a,
    0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a,
};

inline void disas_x86(const void* ptr, size_t len)
{
  slankdev::capstone c;
  c.disasm(ptr, len, 0x000, 0);
  for (size_t i = 0; i < c.insn_len(); i++) {
    const cs_insn* insn = c.get_insn();
    printf("0x%04lx:    %-5s %-20s   ",
        insn[i].address,
        insn[i].mnemonic,
        insn[i].op_str
    );
    for (size_t j=0; j<insn[i].size; j++) {
      printf("%02x ", insn[i].bytes[j]);
    }
    printf("\n");

    if (strcmp(insn[i].mnemonic, "nop") == 0) break;
  }
}




static inline const char* num2lavel(size_t n)
{
  static std::string s;
  s = "." + std::to_string(n);
  return s.c_str();
}




class bpf_arp : public Xbyak::CodeGenerator {

  /*
   * (000) ldh      [12]
   * (001) jeq      #0x806           jt 2    jf 3
   * (002) ret      #262144
   * (003) ret      #0
   */

	void operator=(const bpf_arp&);
 public:
	bpf_arp(void *userPtr = 0, size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE)
    : Xbyak::CodeGenerator(size, userPtr)
	{
    inLocalLabel();

   L(num2lavel(0)); /* ldh [12] */
    mov(cx, dword [edi + 12]);
    bswap(ecx);
    shr(ecx, 16);

   L(num2lavel(1)); /* jeq 0x0806 jt 2 jf 3 */
    cmp(cx, 0x0806);
    jz(num2lavel(2));
    jmp(num2lavel(3));

   L(num2lavel(2)); /* ret 0xffff */
    mov(eax, 0xffff);
    ret();

   L(num2lavel(3)); /* ret 0 */
    mov(eax, 0);
    ret();

    for (size_t i=0; i<100; i++) nop();
    outLocalLabel();
	}
};




class bpf_tcp : public Xbyak::CodeGenerator {

  /*
   * (000) ldh      [12]
   * (001) jeq      #0x800           jt 2   jf 5
   * (002) ldb      [23]
   * (003) jeq      #0x6             jt 4   jf 5
   * (004) ret      #262144
   * (005) ret      #0
   */

	void operator=(const bpf_tcp&);
 public:
	bpf_tcp(void *userPtr = 0, size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE)
    : Xbyak::CodeGenerator(size, userPtr)
	{
    printf("JIT start \n");
    inLocalLabel();

   L(num2lavel(0)); /* ldh [12] */
    mov(cx, dword [edi + 12]);
    bswap(ecx);
    shr(ecx, 16);

   L(num2lavel(1)); /* jeq #0x800 jt 2 jf 5 */
    cmp(ecx, 0x0800);
    jz (num2lavel(2));
    jmp(num2lavel(5));

   L(num2lavel(2)); /* ldb [23] */
    mov(cl, byte [edi + 23]);
    bswap(ecx);
    shr(ecx, 24);

   L(num2lavel(3)); /* jeq #6 jt 4 jf 5 */
    cmp(ecx, 0x06);
    jz (num2lavel(4));
    jmp(num2lavel(5));

   L(num2lavel(4)); /* ret #0xffff */
    mov(eax, 0xffff);
    ret();

   L(num2lavel(5)); /* ret #0 */
    mov(eax, 0);
    ret();

    for (size_t i=0; i<100; i++) nop();
    outLocalLabel();
	}
};





class bpf : public Xbyak::CodeGenerator {
	void operator=(const bpf&);
 public:
	bpf(const char* filter, void *userPtr = 0,
      size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE)
    : Xbyak::CodeGenerator(size, userPtr)
	{
    slankdev::pcap pcap;
    pcap.open_dead();

    struct bpf_program prog;
    pcap.compile(&prog, filter, 1, 0xffffff00);
    printf("bpf dissasemble\n");
    slankdev::dissas(prog.bf_insns, prog.bf_len);

    using namespace slankdev;
    inLocalLabel();

    size_t bf_len = prog.bf_len;
    for (size_t i=0; i<bf_len; i++) {

      L(num2lavel(i));

      uint16_t code = prog.bf_insns[i].code;
      uint8_t  jt   = prog.bf_insns[i].jt+i+1;
      uint8_t  jf   = prog.bf_insns[i].jf+i+1;
      uint32_t  k   = prog.bf_insns[i].k;

      switch (code) {
        case LD|H|ABS:
          mov(cx, dword [edi + k]);
          bswap(ecx);
          shr(ecx, 16);
          break;

        case LD|B|ABS:
          mov(cl, byte [edi + k]);
          bswap(ecx);
          shr(ecx, 24);
          break;

        case JMP|JEQ|K:
          cmp(ecx, k);
          jz (num2lavel(jt));
          jmp(num2lavel(jf));
          break;

        case RET|K:
          mov(eax, k);
          ret();
          break;

        default:
          throw slankdev::exception("unknown code");
          break;
      }

    }

    for (size_t i=0; i<100; i++) nop();
    outLocalLabel();
	}
};



int main()
{
  printf("Packet\n");
  slankdev::hexdump(stdout, raw_packet, sizeof(raw_packet));

  bpf s("tcp");
  printf("\n\nBPF JIT with Xbyak%s x86 ASM\n", s.getVersionString());
  int (*func)(const void*,size_t) = s.getCode<int (*)(const void*,size_t)>();
  disas_x86((void*)func, Xbyak::DEFAULT_MAX_CODE_SIZE);

  int ret = func(raw_packet,sizeof(raw_packet));
  printf("\n\nresult: %d (%s)\n", ret, ret==0?"eject":"pass");
}


