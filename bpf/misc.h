
#pragma once
#include <slankdev/extra/capstone.h>
#include <slankdev/extra/bpf.h>
#include <slankdev/extra/pcap.h>



inline void _disas_x86(const void* ptr, size_t len)
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

inline void _disas_bpf(const void* ptr, size_t len)
{ slankdev::dissas(reinterpret_cast<const bpf_insn*>(ptr), len); }


