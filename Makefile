EFIINC          = /usr/include/efi
EFILIB          = /usr/lib
CFLAGS          = -I$(EFIINC) -I$(EFIINC)/x86_64 -I$(EFIINC)/protocol -fno-stack-protector -fpic -fshort-wchar -mno-red-zone -Wall -DEFI_FUNCTION_WRAPPER
LDFLAGS         = -nostdlib -znocombreloc -T $(EFILIB)/elf_x86_64_efi.lds -shared -Bsymbolic -L $(EFILIB) -L /usr/lib $(EFILIB)/crt0-efi-x86_64.o

all: protector.efi skipsign.efi

%.so: %.o
	ld $(LDFLAGS) $< -o $@ -lefi -lgnuefi

%.efi: %.so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel -j .rela -j .reloc --target=efi-app-x86_64 $^ $@
