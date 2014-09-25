grml-plus UEFI Tools
====================

Collection of small tools used to make grml-plus' UEFI support better.

Compiled on Debian Wheezy against GNU EFI.

Currently contains (more to come):

grml-plus UEFI protector
------------------------

As described in http://superuser.com/a/762821/1724 some UEFI implementations
(particularly the one used in my Lenovo L530 notebook) detect when booting an
operating system if anything outside the current BIOS memory map is allocated
by UEFI. In that case, the memory map is adjusted and a reboot is triggered.
In case you first enter UEFI GRUB, try to boot something (which fails) and
then return to the boot menu and decide to boot your normal OS (via CSM
compatibility mode), you will lose a few megabytes of your RAM (until you
manually fix up the MemoryTypeInformation UEFI variable). To avoid this,
grml-plu uses grml-plus UEFI protector as its primary UEFI stub, which
can load GRUB (or MemTest or EFI shells) and will not allow the user to
return to the boot menu after trying to boot in case the aforementioned UEFI
variable exists.

grml-plus SkipSign
------------------

When using Shim or a similar bootloader to allow booting of non-Microsoft
signed EFI binaries in Secure Boot, there is an inherent problem: As many EFI
applications will try to load additional binaries dynamically, this loading
will also be subject to Secure Boot and therefore fail.

SkipSign.efi is a small Shim-like application (to be loaded between the actual
shim and the UEFI protector which will install a Security Policy that will
accept to load all well-formed EFI binaries. This approach is similar to the
approach used by the Linux Foundation's PreLoader, only that it will not
require you to whitelist every single module (therefore providing more
convenience than the PreLoader does).

Note that some firmware implementations (for example, Lenovo's) will still
print a warning whenever an unsigned binary is tried to be loaded - this does
not prevent you from actually using the system, though.
