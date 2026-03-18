
import idc
import idaapi
import ida_kernwin

def dump(dumpfile, startimg, endimg, offset):
    size = endimg - startimg
    dumpfile.seek(offset)
    for i in range(size):
        dumpfile.write(bytes([idc.get_wide_byte(startimg + i)]))

def detect_elf_class(addr):
    """Detect ELF class (32-bit or 64-bit) by reading EI_CLASS at offset 0x4"""
    ei_class = idc.get_wide_byte(addr + 0x4)
    if ei_class == 1:
        return 32
    elif ei_class == 2:
        return 64
    return 0

def dump_elf32(addr, output_path):
    print("--- Start to Dump 32bit ELF (By LeoChen)")
    print(f"Output file: {output_path}")
    dumpfile = open(output_path, "wb")
    e_phoff = addr + idc.get_wide_dword(addr + 0x1C)
    e_phnum = idc.get_wide_word(addr + 0x2C)
    e_phentsize = idc.get_wide_word(addr + 0x2A)
    for i in range(e_phnum):
        if idc.get_wide_dword(e_phoff) == 1 or idc.get_wide_dword(e_phoff) == 2:
            print("- start dump segment %d" % i)
            p_offset = idc.get_wide_dword(e_phoff + 0x4)
            p_vaddr = idc.get_wide_dword(e_phoff + 0x8)
            p_memsz = idc.get_wide_dword(e_phoff + 0x14)
            dump(dumpfile, p_vaddr, p_vaddr + p_memsz, p_offset)
        e_phoff = e_phoff + e_phentsize
    dumpfile.close()
    print("--- Dump OK (By LeoChen)")

def dump_elf64(addr, output_path):
    print("--- Start to Dump 64bit ELF (By LeoChen)")
    print(f"Output file: {output_path}")
    dumpfile = open(output_path, "wb")
    e_phoff = addr + idc.get_wide_dword(addr + 0x20)
    e_phnum = idc.get_wide_word(addr + 0x38)
    e_phentsize = idc.get_wide_word(addr + 0x36)
    for i in range(e_phnum):
        if idc.get_wide_dword(e_phoff) == 1 or idc.get_wide_dword(e_phoff) == 2:
            print("- start dump segment %d" % i)
            p_offset = idc.get_wide_dword(e_phoff + 0x8)
            p_vaddr = idc.get_wide_dword(e_phoff + 0x10)
            p_memsz = idc.get_wide_dword(e_phoff + 0x28)
            dump(dumpfile, p_vaddr, p_vaddr + p_memsz, p_offset)
        e_phoff = e_phoff + e_phentsize
    dumpfile.close()
    print("--- Dump OK (By LeoChen)")

def main(addr=None, output_path=None):
    """Main entry: auto-detect ELF class and dump."""
    if addr is None or output_path is None:
        show_dialog()
        return

    elf_class = detect_elf_class(addr)
    if elf_class == 32:
        dump_elf32(addr, output_path)
    elif elf_class == 64:
        dump_elf64(addr, output_path)
    else:
        print("[!] Error: Not a valid ELF file at 0x%X" % addr)

class ElfDumperDialog(ida_kernwin.Form):
    def __init__(self):
        ida_kernwin.Form.__init__(self, r"""STARTITEM 0
ElfDumper

输入Dump ELF的地址：
<##地址:{iAddr}>
输出文件名：
<##输出文件:{iFile}>
""", {
            'iAddr': ida_kernwin.Form.StringInput(swidth=50, value="0x"),
            'iFile': ida_kernwin.Form.FileInput(save=True, swidth=50, value="ELF.dump"),
        })

def show_dialog():
    dlg = ElfDumperDialog()
    dlg.Compile()
    ok = dlg.Execute()
    if ok == 1:
        addr_str = dlg.iAddr.value.strip()
        output_path = dlg.iFile.value.strip()
        try:
            addr = int(addr_str, 16) if addr_str.startswith("0x") or addr_str.startswith("0X") else int(addr_str)
        except ValueError:
            print("[!] Error: Invalid address: %s" % addr_str)
            dlg.Free()
            return
        if not output_path:
            output_path = "ELF.dump"
        dlg.Free()
        main(addr, output_path)
    else:
        dlg.Free()

class ElfDumperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Dump ELF from memory (auto x86/x64)"
    help = "ElfDumper by LeoChen"
    wanted_name = "ElfDumper"
    wanted_hotkey = "Ctrl+Shift+D"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        show_dialog()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return ElfDumperPlugin()

if __name__ == "__main__":
    show_dialog()
