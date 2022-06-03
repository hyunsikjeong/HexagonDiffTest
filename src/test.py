#!/usr/bin/env python3

import argparse
import copy
import csv
import itertools
import json
import os
import pickle
import random
import re
import socket
import subprocess
from tempfile import NamedTemporaryFile
import threading


insns = {}
ld_set, st_set = set(), set()


def read_instructions_csv():
    global insns, ld_set, st_set

    with open("resources/instructions.csv") as f:
        reader = csv.reader(f)
        rows = list(reader)

    for row in rows:
        insns[row[-1]] = row

    # ALU32 instructions
    insns["alu32"] = rows[:118]
    insns["nop"] = rows[10]

    # CR instructions
    # Slot 2, 3
    insns["cr23"] = rows[118:122] + rows[133:147]
    # Add user control register transfer instructions
    # insns['cr23'] += rows[147:151]
    # Slot 3 only
    # insns['cr3'] = rows[122:133]

    # JR instructions
    # insns['jr'] = rows[151:164]

    # J instructions
    # insns['j'] = rows[164:258]

    # LD instructions
    insns["ld"] = rows[258:470]
    for row in rows[258:470]:
        ld_set.add(row[-1])

    # MEMOP instructions
    insns["memop"] = rows[470:494]

    # NV instructions
    # insns['nv'] = rows[494:616]
    insns["nv/j"] = rows[494:538]
    insns["nv/st"] = rows[538:616]

    # ST instructions
    insns["st"] = rows[616:762]
    for row in rows[616:762]:
        st_set.add(row[-1])

    # SYSTEM instructions
    # insns['system'] = rows[762:843]

    # XTYPE instructions
    insns["xtype"] = rows[843:]


read_instructions_csv()


def signed(v, bit):
    if v >> (bit - 1) == 1:
        t = (v ^ ((1 << bit) - 1)) + 1
        return -t
    else:
        return v


class Instruction:
    opstr_preg = {
        "j": re.compile(r"(#[su][0-9]{1,2})"),
        "I": re.compile(r"(#[SU][0-9]{1,2})"),
        "N": re.compile(r"(\[:<<N\])"),
        **{c: re.compile(r"([RPCMN](" + c + r"{1,2}))(\.new)?") for c in "stuvdexy"},
    }

    def __init__(self, insn_bits, insn_str):
        self.bits = insn_bits
        self.str = insn_str
        self.orig_bits = insn_bits[:]
        self.orig_str = insn_str
        self.written = set()
        self.require = set()
        self.values = dict()
        self.address_mode = None
        self.hints = dict()
        self.invalid = False

    @property
    def insn_byte(self):
        return int("".join(self.bits), 2).to_bytes(4, byteorder="little")

    def print_insn(self, indent=0):
        print(" " * (indent + 49) + "".join(self.orig_bits))
        print(" " * indent + f"{self.str:48s} " + "".join(self.bits))

    def set_value(self, c, val):
        if c != "-":
            self.values[c] = val

        count = self.bits.count(c)
        for idx in range(32):
            if self.bits[idx] == c:
                self.bits[idx] = str((val >> (count - 1)) & 1)
                count -= 1

    def generate_hints(self):
        if self.address_mode is None:
            return

        # TODO: expand targets
        target = 0x410EEE0
        if self.address_mode == "#u6":
            # TODO: Better handling than rejection?
            v = (target - self.values["j"]) % (1 << 32)
            if v & 0b1111111 != 0:
                self.invalid = True
                return
            self.hints["GP"] = v
        elif self.address_mode == "Re=#U6":
            # TODO: Better handling than rejection?
            v = (target - self.values["I"]) % (1 << 32)
            if v & 0b1111111 != 0:
                self.invalid = True
                return
            self.hints["GP"] = v
        elif self.address_mode == "Rt<<#u2+#U6":
            v = target - self.values["I"]
            if v % (1 << self.values["j"]) != 0:
                self.invalid = True
                return
            self.hints[f'R{self.values["t"]}'] = v >> self.values["j"]
        elif self.address_mode == "Ru<<#u2+#U6":
            v = target - self.values["I"]
            if v % (1 << self.values["j"]) != 0:
                self.invalid = True
                return
            self.hints[f'R{self.values["u"]}'] = v >> self.values["j"]
        elif self.address_mode[:-1] == "gp+#u16:":
            # TODO: Better handling than rejection?
            v = (target - (self.values["j"] << int(self.address_mode[-1]))) % (1 << 32)
            if v & 0b1111111 != 0:
                self.invalid = True
                return
            self.hints["GP"] = v
        elif self.address_mode[:-1] == "Rs+#s11:":
            self.hints[f'R{self.values["s"]}'] = target - (
                signed(self.values["j"], 11) << int(self.address_mode[-1])
            )
        elif self.address_mode[:-1] == "Rs+#u6:":
            self.hints[f'R{self.values["s"]}'] = target - (
                self.values["j"] << int(self.address_mode[-1])
            )
        elif self.address_mode == "Rs+Rt<<#u2":
            if self.values["t"] == self.values["s"]:
                mult = 1 + (1 << self.values["j"])
                if target % mult != 0:
                    self.invalid = True
                    return
                self.hints[f'R{self.values["t"]}'] = target // mult
            else:
                t = random.getrandbits(32)
                s = (target - (t << self.values["j"])) % (1 << 32)
                self.hints[f'R{self.values["t"]}'] = t
                self.hints[f'R{self.values["s"]}'] = s
        elif self.address_mode == "Rs+Ru<<#u2":
            if self.values["u"] == self.values["s"]:
                mult = 1 + (1 << self.values["j"])
                if target % mult != 0:
                    self.invalid = True
                    return
                self.hints[f'R{self.values["u"]}'] = target // mult
            else:
                u = random.getrandbits(32)
                s = (target - (u << self.values["j"])) % (1 << 32)
                self.hints[f'R{self.values["u"]}'] = u
                self.hints[f'R{self.values["s"]}'] = s
        elif self.address_mode == "Rx++Mu:brev":
            t = f"{target:032b}"
            t = int(t[:16] + t[16:][::-1], 2)
            self.hints[f'R{self.values["x"]}'] = t
        else:
            self.hints[f'R{self.values["x"]}'] = target

    @classmethod
    def generate(cls, slot, target=None):
        global insns

        if target is None:
            if slot == 0:
                picked_insns = (
                    insns["alu32"] + insns["ld"] + insns["st"] + insns["memop"]
                )
            elif slot == 1:
                picked_insns = insns["alu32"] + insns["st"] + insns["ld"]
            elif slot == 2:
                picked_insns = insns["alu32"] + insns["xtype"] + insns["cr23"]
            elif slot == 3:
                picked_insns = insns["alu32"] + insns["xtype"] + insns["cr23"]

            while True:
                picked = random.choice(picked_insns)[:]
                insn_bits, insn_str = picked[:-1], picked[-1]
                if "deprecated" in insn_str:
                    continue
                # Not possible to handle return instructions
                if "return" in insn_str:
                    continue

                # TODO: Handle those:
                if "(#u6)" in insn_str or "(Re=#U6)" in insn_str:
                    continue

                # Not testing allocframe and deallocframe
                if "allocframe" in insn_str:
                    continue

                insn = cls(insn_bits, insn_str)
                break

        else:
            picked = insns[target]
            insn_bits, insn_str = picked[:-1], picked[-1]
            insn = cls(insn_bits, insn_str)

        # TODO: Support loop end instruction?
        if slot:
            insn.set_value("P", 1)
        else:
            insn.set_value("P", 3)
        insn.set_value("-", 0)

        # Get memory addressing
        regex = re.compile(r"memu?b?[bhwd](?:_fifo)?\(([^\(\)]*(?:\(Mu\))?)\)")
        res = regex.search(insn.str)
        insn.address_mode = res.group(1) if res else None

        for c in "jINstuvdexy":
            count = insn.bits.count(c)
            if count == 0:
                continue

            res = cls.opstr_preg[c].search(insn.str)
            opstr = res.group(1)
            if len(res.groups()) >= 2:
                is_pair = True if res.group(2) and len(res.group(2)) == 2 else False
                is_new_value = True if res.group(3) else False
            else:
                is_pair, is_new_value = False, False

            if c in "jIN":
                val = random.randint(0, 2**count - 1)
            elif is_pair:
                val = random.randint(0, min(2**count - 1, 8))
            else:
                val = random.randint(0, min(2**count - 1, 9))

            if c in "jI":
                if "s" in opstr[1:] or "S" in opstr[1:]:
                    insn.str = insn.str.replace(
                        opstr, "#{}{}".format(signed(val, count), opstr[1:])
                    )
                else:
                    insn.str = insn.str.replace(opstr, "#{}{}".format(val, opstr[1:]))
            elif c == "N" and val:
                assert val == 1
                insn.str = insn.str.replace(opstr, ":<<1")
            elif c == "N" and not val:
                insn.str = insn.str.replace(opstr, "")
            elif is_pair:
                insn.str = insn.str.replace(
                    opstr, "{}{}:{}".format(opstr[0], val + 1, val)
                )
            else:
                insn.str = insn.str.replace(opstr, "{}{}".format(opstr[0], val))

            if is_new_value:
                insn.require |= set(["{}{}".format(opstr[0], val)])
            if c in "dexy":
                if is_pair:
                    insn.written |= set(
                        ["{}{}".format(opstr[0], val), "{}{}".format(opstr[0], val + 1)]
                    )
                else:
                    insn.written |= set(["{}{}".format(opstr[0], val)])

            insn.set_value(c, val)

        if "decbin" in insn.str:
            insn.written.add("P0")

        # Handle memory addressing
        insn.generate_hints()

        return insn

    @classmethod
    def nop(cls, slot):
        nop = cls(insns["nop"][:32], insns["nop"][-1])
        if slot:
            nop.set_value("P", 1)
        else:
            nop.set_value("P", 3)
        nop.set_value("-", 0)
        return nop


class InstructionPacket:
    def __init__(self, insns):
        self.insns = insns
        self.hints = dict()
        self.invalid_hints = False

        for insn in insns:
            for key, value in insn.hints.items():
                if key in self.hints and self.hints[key] != value:
                    self.invalid_hints = True
                else:
                    self.hints[key] = value

    def get_bytes(self):
        return b"".join(insn.insn_byte for insn in reversed(self.insns))

    def is_valid(self):
        if self.invalid_hints:
            return False
        if any(insn.invalid for insn in self.insns):
            return False

        # slot 1 st should be with slot 0 st/ld
        if (
            self.insns[0].orig_str not in ld_set
            and self.insns[0].orig_str not in st_set
            and self.insns[1].orig_str in st_set
        ):
            return False

        # Slot 1 ld should be with slot 0 ld
        if self.insns[0].orig_str not in ld_set and self.insns[1].orig_str in ld_set:
            return False

        all_require = set().union(*[insn.require for insn in self.insns])
        all_written = set().union(*[insn.written for insn in self.insns])
        return len(all_written) == sum(
            len(insn.written) for insn in self.insns
        ) and len(all_require) == len(all_require & all_written)

    def get_written_reg(self):
        return set().union(*[insn.written for insn in self.insns])

    def get_required_insn_index(self, slots):
        all_require = set().union(*[self.insns[i].require for i in slots])
        ret = []
        for i, insn in enumerate(self.insns):
            if insn.written & all_require:
                ret.append(i)
        return ret

    def print_packet(self):
        print("{")
        for insn in self.insns:
            insn.print_insn(indent=4)
        print("}")

    @classmethod
    def generate(cls):
        # Avoid double-writing
        while True:
            insns = [Instruction.generate(slot) for slot in range(4)]
            packet = cls(insns)
            if not packet.is_valid():
                continue
            return packet

    @classmethod
    def generate_with_target(cls, target):
        # Avoid double-writing
        while True:
            insns = [Instruction.generate(slot, target[slot]) for slot in range(4)]
            packet = cls(insns)
            if not packet.is_valid():
                continue
            return packet


class TestCase:
    def __init__(self, packet, input):
        self.packet = packet
        self.input = input

    @staticmethod
    def generate_input(packet):
        with open("/dev/urandom", "rb") as f:
            general = b""
            for i in range(10):
                v = f.read(4)
                if f"R{i}" in packet.hints:
                    v = packet.hints[f"R{i}"] % (1 << 32)
                    v = v.to_bytes(4, "little")
                general += v

            predicate = b""
            for _ in range(4):
                t = random.randint(0, 2)
                if t == 0:
                    predicate += b"\x00"
                elif t == 1:
                    predicate += b"\xff"
                else:
                    predicate += f.read(1)

            m0m1 = f.read(4 * 2)

            user_status = bytearray(f.read(4))
            user_status[0] &= 0b00111110
            user_status[1] &= 0b11111100
            user_status[2] &= 0b11000001
            user_status[
                3
            ] &= (
                0b00000000  # TODO: What the hell is wrong with IEEE trap enable fields?
            )

            # [16:15] HFI cannot be 11
            if user_status[1] & 0b10000000 and user_status[2] & 0b00000001:
                user_status[1] &= 0b01111111
                user_status[2] &= 0b11111110

            gp = bytearray(f.read(4))
            gp[0] &= 0b10000000
            if "GP" in packet.hints:
                gp = packet.hints[f"GP"].to_bytes(4, "little")

            cs = f.read(8)

            mem = f.read(4 * 4)

        return general + predicate + m0m1 + user_status + gp + cs + mem

    @classmethod
    def generate(cls, db=None):
        while True:
            packet = InstructionPacket.generate()
            input = cls.generate_input(packet)
            tc = cls(packet, input)
            if db and db.check(tc):
                continue
            return tc

    @classmethod
    def generate_with_target(cls, target):
        packet = InstructionPacket.generate_with_target(target)
        input = cls.generate_input(packet)
        tc = cls(packet, input)
        return tc

    def mutate(self, slots, db=None):
        required_index = self.packet.get_required_insn_index(slots)

        while True:
            packet = copy.deepcopy(self.packet)
            for i in range(4):
                if i in slots:
                    continue
                if i in required_index:
                    while True:
                        insn = Instruction.generate(i)
                        if packet.insns[i].written == insn.written:
                            packet.insns[i] = insn
                            break
                else:
                    packet.insns[i] = Instruction.nop(i)

            input = self.generate_input(packet)
            tc = self.__class__(packet, input)

            if db and db.check(tc):
                continue
            return tc

    def print_testcase(self):
        self.packet.print_packet()
        print(self.input.hex())


class Emulator:
    def __init__(self, name):
        self.name = name

    def run(self, testcase):
        raise NotImplemented

    @staticmethod
    def parse_output(output):
        prog = re.compile(rb"((?:R|C|Mem)[0-9]{1,2}): ([0-9]{1,10})")

        inputs, outputs = {}, {}
        for line in output.split(b"\n"):
            res = prog.match(line)
            if not res:
                continue
            name, value = res.group(1).decode(), int(res.group(2))

            if name not in inputs:
                inputs[name] = value
            else:
                outputs[name] = value

        return {"input": inputs, "output": outputs}


class SimEmulator(Emulator):
    def __init__(self):
        super().__init__("sdk-sim")

    def run(self, testcase):
        with open("bin/template.elf", "rb") as f:
            data = bytearray(f.read())

        # Find 4 nops to replace
        nops = (
            data.find(
                b"\x0d\xc0\x31\x62"
                + b"\x00\x40\x00\x7f" * 3
                + b"\x00\xc0\x00\x7f"
                + b"\x0b\xc0\x04\x6a"
            )
            + 4
        )
        data[nops : nops + 16] = testcase.packet.get_bytes()

        file = NamedTemporaryFile(delete=False)
        file.write(data)
        os.chmod(file.name, 0o555)
        file.close()

        proc = subprocess.run(
            ["make", "sim", "MAIN_BIN=" + file.name, "-s"],
            input=testcase.input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        os.remove(file.name)

        if b"CRASH" in proc.stdout:
            return None
        return self.parse_output(proc.stdout)


class QemuEmulator(Emulator):
    def __init__(self):
        super().__init__("qemu")

    def run(self, testcase):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("localhost", 9000))
            s.send(testcase.packet.get_bytes() + testcase.input)
            data = s.recv(1024)

        if b"CRASH" in data:
            return None
        return self.parse_output(data)


class BinjaEmulator(Emulator):
    def __init__(self):
        super().__init__("binja")
        with open("./binja_template.elf", "rb") as f:
            self.data = bytearray(f.read())
        self.nops = self.data.find((b"\x00\x40\x00\x7f" * 3 + b"\x00\xc0\x00\x7f") * 2)

    def run(self, testcase):
        self.data[self.nops : self.nops + 16] = testcase.packet.get_bytes()

        file = NamedTemporaryFile(delete=False)
        file.write(self.data)
        file.close()

        proc = subprocess.run(
            ["python3", "test_binja.py", file.name],
            input=testcase.input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        os.remove(file.name)

        if proc.stderr:
            # TODO: Implement Exceptions
            print("BinjaEmulator ERROR")
            print(proc.stderr)
            return None

        self.insns, output = proc.stdout.split(b"[OUTPUTS]\n")
        if b"undefined" in self.insns:
            # TODO: Handle this properly
            return -1

        return self.parse_output(output)


class Tester:
    registers = ["R{}".format(i) for i in range(10)] + [
        "C4",
        "C6",
        "C7",
        "C8",
        "C11",
        "C12",
        "C13",
    ]
    memories = ["Mem{}".format(i) for i in range(4)]

    def __init__(self):
        self.testcase = None
        self.output = None
        self.emulators = [
            SimEmulator(),
            QemuEmulator(),
            BinjaEmulator(),
        ]

    def run(self, testcase):
        self.testcase = testcase
        self.output = {}
        for emulator in self.emulators:
            output = emulator.run(testcase)
            if output != -1:
                self.output[emulator.name] = output

    def is_failed(self):
        if len(self.output) != 3:
            return False

        if any(v is None for v in self.output.values()):
            return True

        if self.output["sdk-sim"]["input"] != self.output["binja"]["input"]:
            return True
        if self.output["qemu"]["input"] != self.output["binja"]["input"]:
            return True
        if self.output["sdk-sim"]["output"] != self.output["binja"]["output"]:
            return True
        if self.output["qemu"]["output"] != self.output["binja"]["output"]:
            return True

        written = self.testcase.packet.get_written_reg() | set(["C4", "C8"])
        not_written = set(self.registers) - written
        for _, emulator_case in self.output.items():
            for reg in not_written:
                if emulator_case["input"][reg] != emulator_case["output"][reg]:
                    return True

        return False

    def print_output(self):
        print("[Testcase]")
        self.testcase.print_testcase()

        if len(self.output) == 3:
            print("[Binja output]")
            print(self.emulators[2].insns.decode())

        print("[Input Registers]")
        print(" " * 10 + "".join(f" {r:8s}" for r in self.registers))
        for e in self.emulators:
            s = f"{e.name:10s}"
            if e.name in self.output and self.output[e.name]:
                s += "".join(
                    f" {self.output[e.name]['input'][r]:08x}" for r in self.registers
                )
            else:
                s += "     None" * len(self.registers)
            if e.name in self.output:
                print(s)

        print("[Input Memories]")
        print(" " * 10 + "".join(f" {r:8s}" for r in self.memories))
        for e in self.emulators:
            s = f"{e.name:10s}"
            if e.name in self.output and self.output[e.name]:
                s += "".join(
                    f" {self.output[e.name]['input'][r]:08x}" for r in self.memories
                )
            else:
                s += "     None" * len(self.memories)
            if e.name in self.output:
                print(s)

        print("[Output Registers]")
        print(" " * 10 + "".join(f" {r:8s}" for r in self.registers))
        for e in self.emulators:
            s = f"{e.name:10s}"
            if e.name in self.output and self.output[e.name]:
                s += "".join(
                    f" {self.output[e.name]['output'][r]:08x}" for r in self.registers
                )
            else:
                s += "     None" * len(self.registers)
            if e.name in self.output:
                print(s)

        print("[Output Memories]")
        print(" " * 10 + "".join(f" {r:8s}" for r in self.memories))
        for e in self.emulators:
            s = f"{e.name:10s}"
            if e.name in self.output and self.output[e.name]:
                s += "".join(
                    f" {self.output[e.name]['output'][r]:08x}" for r in self.memories
                )
            else:
                s += "     None" * len(self.memories)
            if e.name in self.output:
                print(s)


class TestCaseDatabase:
    def __init__(self, db=None, path="tc_database.pickle"):
        if db is None:
            self.db = set()
        else:
            self.db = db
        self.path = path
        self.lock = threading.Lock()

    @classmethod
    def load(cls, path="tc_database.pickle"):
        try:
            with open(path, "rb") as f:
                db = pickle.load(f)
                return cls(db, path)
        except:
            return cls()

    def save(self):
        self.lock.acquire()
        with open(self.path, "wb") as f:
            pickle.dump(self.db, f)
        self.lock.release()

    def insert(self, tc, slots):
        self.lock.acquire()
        key = frozenset([tc.packet.insns[i].orig_str for i in slots])
        if key not in self.db:
            self.db.add(key)
        self.lock.release()

    def check(self, tc):
        insn_orig_strs = [insn.orig_str for insn in tc.packet.insns]
        for n in range(1, 5):
            for key in itertools.combinations(insn_orig_strs, n):
                if frozenset(key) in self.db:
                    return True
        return False


class ThreadedTester:
    slots_combination = sum(
        [list(itertools.combinations([0, 1, 2, 3], n)) for n in range(1, 5)], []
    )

    def __init__(self, num_thread, target_packet=None):
        self.tc_database = TestCaseDatabase().load()
        self.num_thread = num_thread
        self.print_lock = threading.Lock()
        self.target_packet = target_packet
        self.run_thread = (
            self.run_thread_with_target if target_packet else self.run_thread_no_target
        )

    def run(self):
        for _ in range(self.num_thread):
            threading.Thread(target=self.run_thread).start()

    def run_thread_with_target(self):
        tester = Tester()
        while True:
            tc = TestCase.generate_with_target(self.target_packet)
            tester.run(tc)
            if not tester.is_failed():
                continue

            self.print_lock.acquire()
            tester.print_output()
            print("=" * 118)
            self.print_lock.release()

    def run_thread_no_target(self):
        tester = Tester()
        mutate_tester = Tester()
        while True:
            tc = TestCase.generate(db=self.tc_database)
            tester.run(tc)
            if not tester.is_failed():
                continue

            identified = None
            for slots in self.slots_combination:
                flag = False
                for _ in range(500):
                    mutated_tc = tc.mutate(slots, db=self.tc_database)
                    mutate_tester.run(mutated_tc)
                    if mutate_tester.is_failed():
                        flag = True
                        break
                if flag:
                    identified = slots
                    break

            # Save to DB
            if identified:
                self.tc_database.insert(tc, identified)
                self.tc_database.save()

            # Print
            self.print_lock.acquire()
            tester.print_output()
            if identified:
                print("Identified, ", identified)
            else:
                print("Failed to identify")
            print("=" * 118)
            self.print_lock.release()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c", "--num-cores", type=int, default=20, help="The number of cores to use"
    )

    parser.add_argument(
        "-t",
        "--target-packet",
        help="The file containing the packet specification to fix the target packet",
    )

    args = parser.parse_args()

    if args.target_packet:
        target_packet = json.load(open(args.target_packet, "r"))
    else:
        target_packet = None

    threaded_tester = ThreadedTester(args.num_cores, target_packet)
    threaded_tester.run()


if __name__ == "__main__":
    main()
