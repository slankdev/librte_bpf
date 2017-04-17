
#include <slankdev/hexdump.h>
#include <slankdev/packet.h>
#include <slankdev/extra/bpf.h>
#include <slankdev/extra/pcap.h>
#include <slankdev/extra/capstone.h>

#define XBYAK_NO_OP_NAMES
#include <xbyak/xbyak.h>



class bpf : public Xbyak::CodeGenerator {
	void operator=(const bpf&);
 public:
	bpf(struct bpf_program* prog, void *userPtr = 0, size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE)
    : Xbyak::CodeGenerator(size, userPtr)
	{
    printf("bpf dissasemble\n");
    for (size_t i=0; i<prog->bf_len; i++) {
      printf("(%03zd) %04x %02x %02x %08x      %s \n",
          i,
          prog->bf_insns[i].code,
          prog->bf_insns[i].jt,
          prog->bf_insns[i].jf,
          prog->bf_insns[i].k,
          slankdev::dissasemble_instruction(&prog->bf_insns[i]).c_str()
      );
    }
    printf("\n");

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



    // using namespace slankdev;
    // for (size_t i=0; i<prog->bf_len; i++) {
    //   struct bpf_insn insn = prog->bf_insns[i];
    //   uint16_t code = insn.code;
    //   uint8_t  jt   = insn.jt;
    //   uint8_t  jf   = insn.jf;
    //   uint32_t k    = insn.k;
    //
    //   printf("(%03u)  ", i);
    //   L(std::to_string(i).c_str());
    //
    //   switch (code) {
    //
    //     case LD|H|ABS:
    //       printf("ldh [%u]\n", k);
    //       mov(cx, ptr [edi + k]);
    //       break;
    //
    //     case LD|B|ABS:
    //       printf("ldb [%u]\n", k);
    //       mov(ecx, byte [edi + k]);
    //       break;
    //
    //     case JMP|JEQ|K:
    //       printf("jeq 0x%x jt=%u, jf=%u\n", k, jt+i+1, jf+i+1);
    //       cmp(ecx, k);
    //       jz(std::to_string(jt+i).c_str());
    //       jmp(std::to_string(jf+i).c_str());
    //       break;
    //
    //     case RET|K:
    //       printf("ret %u\n", k);
    //       mov(eax, k);
    //       ret();
    //       break;
    //
    //     default:
    //       throw slankdev::exception("unknow opcode");
    //       break;
    //
    //   }
    // }
    // printf("\n");

    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();
    nop();

	}
};



int main()
{
  slankdev::pcap pcap;
  pcap.open_dead();

  struct bpf_program prog;
  pcap.compile(&prog, "ip", 0, 0xffffff00);

  bpf s(&prog);
  printf("BPF JIT with Xbyak%s x86 ASM\n", s.getVersionString());

  int (*func)(const void*,size_t) = s.getCode<int (*)(const void*,size_t)>();
  slankdev::hexdump(stdout, slankdev::raw_arp_pack(), 42);
  const uint8_t* pack = slankdev::raw_arp_pack();
  int ret = func(pack,42);
  printf("result: %d\n", ret);

  slankdev::capstone c;
  c.disasm((void*)func, 40, 0x1000, 0);
  for (size_t i = 0; i < c.insn_len(); i++) {
    const cs_insn* insn = c.get_insn();
    printf("0x%lu:    %-5s %-20s   ",
        insn[i].address,
        insn[i].mnemonic,
        insn[i].op_str
    );
    for (size_t j=0; j<insn[i].size; j++) {
      printf("%02x ", insn[i].bytes[j]);
    }
    printf("\n");
  }

}


