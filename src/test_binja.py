import binaryninja
import emilator
import sys

assert len(sys.argv) == 2

CONTROL_REGS = [
    (4, "P3:0"),
    (6, "M0"),
    (7, "M1"),
    (8, "USR"),
    (11, "GP"),
    (12, "CS0"),
    (13, "CS1"),
]

inp = sys.stdin.buffer.read()
inp = [
    int.from_bytes(inp[i : i + 4], byteorder="little") for i in range(0, len(inp), 4)
]

bv = binaryninja.BinaryViewType.get_view_of_file(sys.argv[1])

for func in bv.functions:
    if func.name != "main":
        continue

    for block in func.llil:
        for insn in block:
            print(insn)

    print("[OUTPUTS]")

    emilator = emilator.Emilator(func.llil)
    emilator.map_memory(0x410E000)
    for i in range(10):
        emilator.set_register_value(f"R{i}", inp[i])
        print(f"R{i}: {inp[i]}")
    for i in range(7):
        idx, name = CONTROL_REGS[i]
        emilator.set_register_value(name, inp[i + 10])
        print(f"C{idx}: {inp[i + 10]}")
    for i in range(4):
        addr = 0x410EEE0 + 4 * i
        emilator.write_memory(addr, inp[i + 17], 4)
        print(f"Mem{i}: {inp[i + 17]}")

    emilator.run()

    for i in range(10):
        v = emilator.get_register_value(f"R{i}")
        print(f"R{i}: {v}")
    for idx, name in CONTROL_REGS:
        v = emilator.get_register_value(name)
        print(f"C{idx}: {v}")
    for i in range(4):
        addr = 0x410EEE0 + 4 * i
        v = emilator.read_memory(addr, 4)
        print(f"Mem{i}: {v}")
