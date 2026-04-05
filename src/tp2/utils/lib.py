import string

from src.tp2.utils.config import logger


def get_shellcode_strings(shellcode: bytes, min_len: int = 4) -> str:
    """
    Extract printable ASCII strings from raw shellcode bytes.


    :param shellcode: raw shellcode bytes
    :param min_len: minimum string length to keep
    :return: extracted strings joined by newline
    """
    printable = set(string.printable) - set("\t\n\r\x0b\x0c")
    result = []
    current = []

    for byte in shellcode:
        ch = chr(byte)
        if ch in printable:
            current.append(ch)
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []

    if len(current) >= min_len:
        result.append("".join(current))

    return "\n".join(result) if result else "No strings found."


def get_capstone_analysis(shellcode: bytes) -> str:
    """
    Disassemble shellcode using Capstone (x86 32-bit)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(shellcode, 0x1000):
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

    :param shellcode: raw shellcode bytes
    :return: disassembly as string
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = [
        f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
        for i in md.disasm(shellcode, 0x1000)
    ]
    return "\n".join(lines) if lines else "No instructions disassembled."


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """
    Emulate shellcode using pylibemu
        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(shellcode)
        emulator.prepare(shellcode, offset)
        emulator.test()
        print(emulator.emu_profile_output)

    :param shellcode: raw shellcode bytes
    :return: emulation profile output as string
    """
    try:
        import pylibemu

        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(shellcode)
        offset = max(0, offset)
        emulator.prepare(shellcode, offset)
        emulator.test()
        output = emulator.emu_profile_output
        return output if output else "No pylibemu output."
    except ImportError:
        logger.warning("pylibemu not available — skipping emulation")
        return "pylibemu not available (requires Linux/Exegol to install)"
