
#pragma once

#define XBYAK_NO_OP_NAMES
#include <xbyak/xbyak.h>
#include <slankdev/extra/bpf.h>
#include <slankdev/extra/pcap.h>
#include "misc.h"


class bpf : public Xbyak::CodeGenerator {
  struct bpf_program prog;
  static const char* num2lavel(size_t n)
  {
    static std::string s;
    s = "." + std::to_string(n);
    return s.c_str();
  }
	void operator=(const bpf&);
 public:
  struct bpf_program bpf_compile(const char* filter) const
  {
    struct bpf_program p;
    slankdev::pcap pcap;
    pcap.open_dead();
    pcap.compile(&p, filter, 1, 0xffffff00);
    return p;
  }
  bpf(const struct bpf_program* pgm, void* userPtr = 0)
    : Xbyak::CodeGenerator(Xbyak::DEFAULT_MAX_CODE_SIZE, userPtr)
  { this->prog = *pgm; }
	bpf(const char* filter, void *userPtr = 0)
    : Xbyak::CodeGenerator(Xbyak::DEFAULT_MAX_CODE_SIZE, userPtr)
	{
    inLocalLabel();
    using namespace slankdev;
    prog = bpf_compile(filter);

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
          jz (num2lavel(jt), T_NEAR);
          jmp(num2lavel(jf), T_NEAR);
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

  void debug(const Xbyak::Reg32& r, const char* msg="")
  {
    static const char* str = "DebugPring %s=0x%x msg=%s\n";
    mov(edi, (size_t)str);
    mov(esi, (size_t)r.toString());
    mov(edx, r);
    mov(ecx, (size_t)msg);
    mov(eax, 0);
    call((void*)printf);
  }

  int operator()(const void* packet, size_t packet_len) const
  { return getCode<int(*)(const void*,size_t)>()(packet, packet_len); }
  void disas_bpf() const
  { _disas_bpf(prog.bf_insns, prog.bf_len); }
  void disas_x86() const
  {
    int (*func)(const void*,size_t) = getCode<int (*)(const void*,size_t)>();
    _disas_x86((void*)func, Xbyak::DEFAULT_MAX_CODE_SIZE);
  }

};


