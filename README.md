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
