#!/usr/bin/env python3
"""Directed one-instruction x86-64 state checks against Triton.

Run with the Python interpreter that has triton-library installed. The native
semantic gate independently compares complete functions and generated code.
"""

import unittest

from triton import ARCH, Instruction, TritonContext


MASK = (1 << 64) - 1
SIGN = 1 << 63
FLAGS = ("cf", "zf", "sf", "of")


def step(hex_bytes, *, address=0x1000, memory=None, **registers):
    context = TritonContext(ARCH.X86_64)
    for name, value in {"rsp": 0x9000, **registers}.items():
        context.setConcreteRegisterValue(getattr(context.registers, name), value)
    for location, value in (memory or {}).items():
        context.setConcreteMemoryAreaValue(location, value.to_bytes(8, "little"))
    instruction = Instruction(bytes.fromhex(hex_bytes))
    instruction.setAddress(address)
    context.processing(instruction)
    return context


def reg(context, name):
    return context.getConcreteRegisterValue(getattr(context.registers, name))


def arithmetic_flags(left, right, result, subtract):
    if subtract:
        carry = left < right
        overflow = bool(((left ^ right) & (left ^ result) & SIGN) != 0)
    else:
        carry = result < left
        overflow = bool((~(left ^ right) & (left ^ result) & SIGN) != 0)
    return (int(carry), int(result == 0), int(bool(result & SIGN)), int(overflow))


class InstructionOracleTests(unittest.TestCase):
    def assert_flags(self, context, expected):
        self.assertEqual(tuple(reg(context, flag) for flag in FLAGS), expected)

    def test_full_and_partial_register_writes_and_lea(self):
        for value in (0, 1, SIGN, MASK):
            self.assertEqual(reg(step("4889f8", rdi=value), "rax"), value)
            self.assertEqual(reg(step("89f8", rdi=value, rax=MASK), "rax"), value & 0xffffffff)
        self.assertEqual(reg(step("b8ffffffff", rax=SIGN), "rax"), 0xffffffff)
        context = step("488d44b707", rdi=MASK, rsi=SIGN)
        self.assertEqual(reg(context, "rax"), (MASK + SIGN * 4 + 7) & MASK)

    def test_add_sub_cmp_and_test_flags(self):
        values = (0, 1, 2, SIGN - 1, SIGN, MASK)
        for left in values:
            for right in values:
                for opcode, subtract in (("4801f0", False), ("4829f0", True)):
                    result = (left - right if subtract else left + right) & MASK
                    context = step(opcode, rax=left, rsi=right)
                    self.assertEqual(reg(context, "rax"), result)
                    self.assert_flags(context, arithmetic_flags(left, right, result, subtract))
                compared = (left - right) & MASK
                context = step("4839f7", rdi=left, rsi=right)
                self.assertEqual(reg(context, "rdi"), left)
                self.assert_flags(context, arithmetic_flags(left, right, compared, True))
                context = step("4885f7", rdi=left, rsi=right)
                tested = left & right
                self.assertEqual(reg(context, "rdi"), left)
                self.assert_flags(context, (0, int(tested == 0), int(bool(tested & SIGN)), 0))

    def test_immediate_scalar_operands(self):
        constant = 0xdeadbeef00000001
        immediate = "48b8" + constant.to_bytes(8, "little").hex()
        self.assertEqual(reg(step(immediate), "rax"), constant)
        for left in (0, 1, SIGN, MASK):
            for opcode, subtract in (("4883c001", False), ("4883e801", True)):
                result = (left - 1 if subtract else left + 1) & MASK
                context = step(opcode, rax=left)
                self.assertEqual(reg(context, "rax"), result)
                self.assert_flags(context, arithmetic_flags(left, 1, result, subtract))
            compared = (left - 1) & MASK
            context = step("4883f801", rax=left)
            self.assertEqual(reg(context, "rax"), left)
            self.assert_flags(context, arithmetic_flags(left, 1, compared, True))
            context = step("48f7c001000000", rax=left)
            self.assert_flags(context, (0, int((left & 1) == 0), 0, 0))

    def test_all_supported_conditional_branches(self):
        conditions = {
            "74": lambda c, z, s, o: z, "75": lambda c, z, s, o: not z,
            "7f": lambda c, z, s, o: not z and s == o,
            "7d": lambda c, z, s, o: s == o,
            "7c": lambda c, z, s, o: s != o,
            "7e": lambda c, z, s, o: z or s != o,
            "77": lambda c, z, s, o: not c and not z,
            "73": lambda c, z, s, o: not c,
            "72": lambda c, z, s, o: c,
            "76": lambda c, z, s, o: c or z,
            "78": lambda c, z, s, o: s,
            "79": lambda c, z, s, o: not s,
            "70": lambda c, z, s, o: o,
            "71": lambda c, z, s, o: not o,
        }
        for opcode, predicate in conditions.items():
            for bits in range(16):
                flags = tuple((bits >> index) & 1 for index in range(4))
                context = step(opcode + "05", **dict(zip(FLAGS, flags)))
                expected = 0x1007 if predicate(*flags) else 0x1002
                self.assertEqual(reg(context, "rip"), expected, (opcode, flags))
                self.assert_flags(context, flags)

    def test_stack_local_call_and_return_effects(self):
        pushed = step("55", rbp=0x12345678)
        self.assertEqual(reg(pushed, "rsp"), 0x8ff8)
        self.assertEqual(int.from_bytes(pushed.getConcreteMemoryAreaValue(0x8ff8, 8), "little"),
                         0x12345678)
        popped = step("5d", memory={0x9000: 0x12345678})
        self.assertEqual((reg(popped, "rsp"), reg(popped, "rbp")),
                         (0x9008, 0x12345678))
        stored = step("48897df8", rbp=0x9000, rdi=SIGN)
        self.assertEqual(int.from_bytes(stored.getConcreteMemoryAreaValue(0x8ff8, 8), "little"),
                         SIGN)
        loaded = step("488b45f8", rbp=0x9000, memory={0x8ff8: MASK})
        self.assertEqual(reg(loaded, "rax"), MASK)
        called = step("e800000000")
        self.assertEqual(reg(called, "rsp"), 0x8ff8)
        self.assertEqual(int.from_bytes(called.getConcreteMemoryAreaValue(0x8ff8, 8), "little"),
                         0x1005)
        returned = step("c3", memory={0x9000: 0x12345678})
        self.assertEqual((reg(returned, "rsp"), reg(returned, "rip")),
                         (0x9008, 0x12345678))

    def test_frame_adjustments_and_direct_jump(self):
        lowered = step("4883ec08")
        self.assertEqual(reg(lowered, "rsp"), 0x8ff8)
        self.assert_flags(lowered, arithmetic_flags(0x9000, 8, 0x8ff8, True))
        raised = step("4883c408", rsp=0x8ff8)
        self.assertEqual(reg(raised, "rsp"), 0x9000)
        self.assert_flags(raised, arithmetic_flags(0x8ff8, 8, 0x9000, False))
        self.assertEqual(reg(step("4889e5"), "rbp"), 0x9000)
        self.assertEqual(reg(step("4889ec", rbp=0x8800), "rsp"), 0x8800)
        leaving = step("c9", rbp=0x8ff8, memory={0x8ff8: 0x1234})
        self.assertEqual((reg(leaving, "rsp"), reg(leaving, "rbp")), (0x9000, 0x1234))
        self.assertEqual(reg(step("eb05"), "rip"), 0x1007)
        self.assertEqual(reg(step("90", rdi=123), "rdi"), 123)


if __name__ == "__main__":
    unittest.main()
