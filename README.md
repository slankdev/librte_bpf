
# bpf

BPF Implementation using Xbyak JIT Assembler in Userland

## Usage

Before install, required package installation. Following package are required.

- Xbyak
- libslankdev
- libpcap
- libcapstone

```
$ sudo apt install libpcap-dev
$ sudo apt install libcapstone-dev
$ git clone http://github.com/slankdev/libslankdev.git
$ cd libslankdev; sudo make install; cd ..
$ git clone http://github.com/herumi/xbyak.git
$ cd xbyak; sudo make install; cd ..
```

```
$ git clone https://github.com/susanow/bpf.git
$ cd bpf
$ sudo make install
$ sudo make uninstall
```

## Sample

```
#include <stdio.h>
#include <bpf/bpf.h>

int main()
{
  uint8_t packet[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00
  };

  bpf filter("tcp port 80");
  int ret = filter(packet, sizeof(packet));
  if (ret!=0) puts("pass");
  else        puts("eject");
}
```


