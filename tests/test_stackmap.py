"""Unit tests for the optional StackMapTable declared-frame check."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.verifier import verify_class  # noqa: E402
from builder import (Asm, ClassBuilder, Sm, legal_construction_class,  # noqa: E402
                     stackmap_legal_class, stackmap_mismatch_class,
                     u2, vt_int, vt_null, vt_object, vt_top, vt_uninit)

DIAG = "com/acme/Diag"


def diag_builder():
    b = ClassBuilder()
    x = b.cp.cls(DIAG)
    init = b.cp.methodref(DIAG, "<init>", "()V")
    return b, x, init


class ToggleCompatTests(unittest.TestCase):
    def test_toggle_off_ignores_malformed_stackmap(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=b"\xff\xff\xff")  # garbage body
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertNotIn("stackmap", res)

    def test_toggle_on_reads_the_same_garbage_and_rejects(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=b"\xff\xff\xff")
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")
        self.assertIn("stackmap", res)

    def test_toggle_off_response_shape_unchanged(self):
        res = verify_class(stackmap_legal_class())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertNotIn("stackmap", res)

    def test_no_stackmap_attribute_passes_with_empty_frames(self):
        res = verify_class(legal_construction_class(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["stackmap"]["attribute_offset"], None)
        self.assertEqual(res["stackmap"]["frames"], [])


class DeclaredFramePassTests(unittest.TestCase):
    def test_legal_stackmap_frames_reported(self):
        res = verify_class(stackmap_legal_class(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        sm = res["stackmap"]
        self.assertIsInstance(sm["attribute_offset"], int)
        frames = sm["frames"]
        self.assertEqual([f["offset"] for f in frames], [9, 11, 26, 28])
        self.assertEqual([f["frame_type"] for f in frames],
                         ["same", "same", "append", "full"])
        self.assertEqual([f["offset_delta"] for f in frames], [9, 1, 14, 1])
        for f in frames:
            self.assertTrue(f["reachable"])
            self.assertIsInstance(f["table_offset"], int)
        self.assertEqual(frames[0]["declared_locals"], [])
        self.assertEqual(frames[0]["locals"], ["top", "top"])
        self.assertEqual(frames[2]["declared_locals"], ["int"])
        self.assertEqual(frames[2]["locals"], ["int", "top"])
        self.assertEqual(frames[3]["declared_locals"], ["int", f"ref {DIAG}"])
        self.assertEqual(frames[3]["locals"], ["int", f"ref {DIAG}"])
        self.assertEqual(frames[3]["declared_stack"], [])

    def test_same_locals_1_stack_item_compact_and_extended(self):
        for extended in (False, True):
            with self.subTest(extended=extended):
                b = ClassBuilder()
                a = Asm()
                a.op(0x03)              # 0 iconst_0
                a.branch(0x99, "l1")    # 1 ifeq l1
                a.op(0x04)              # 4 iconst_1
                a.branch(0xA7, "j")     # 5 goto j
                a.label("l1")           # 8
                a.op(0x05)              # 8 iconst_2
                a.label("j")            # 9
                a.op(0x3B)              # 9 istore_0
                a.op(0x1A)              # 10 iload_0
                a.op(0x57)              # 11 pop
                a.op(0xB1)              # 12 return
                code = a.build()
                sm = Sm().same1(a.labels["j"], vt_int(), extended=extended)
                b.add_method("run", code, max_stack=1, max_locals=1,
                             stackmap=sm.build())
                res = verify_class(b.build(), check_stackmap=True)
                self.assertTrue(res["ok"], res.get("error"))
                f = res["stackmap"]["frames"][0]
                self.assertEqual(f["frame_type"], "same_locals_1_stack_item")
                self.assertEqual(f["offset"], 9)
                self.assertEqual(f["declared_stack"], ["int"])
                self.assertEqual(f["stack"], ["int"])

    def test_same_frame_extended_and_append(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "l1")    # 1 ifeq l1
        a.op(0x04)              # 4 iconst_1
        a.op(0x3B)              # 5 istore_0
        a.branch(0xA7, "j1")    # 6 goto j1
        a.label("l1")           # 9
        a.op(0x05)              # 9 iconst_2
        a.op(0x3B)              # 10 istore_0
        a.label("j1")           # 11
        a.op(0x03)              # 11 iconst_0
        a.branch(0x99, "l2")    # 12 ifeq l2
        a.op(0x1A)              # 15 iload_0
        a.op(0x57)              # 16 pop
        a.branch(0xA7, "e")     # 17 goto e
        a.label("l2")           # 20
        a.op(0x00)              # 20 nop
        a.label("e")            # 21
        a.op(0xB1)              # 21 return
        code = a.build()
        sm = (Sm()
              .same(a.labels["l1"])                          # @9  locals []
              .append(a.labels["j1"] - a.labels["l1"] - 1,
                      [vt_int()])                            # @11 locals [int]
              .same(a.labels["l2"] - a.labels["j1"] - 1,
                    extended=True))                          # @20 locals [int]
        b.add_method("run", code, max_stack=1, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        frames = res["stackmap"]["frames"]
        self.assertEqual([f["offset"] for f in frames], [9, 11, 20])
        self.assertEqual(frames[2]["frame_type"], "same")
        self.assertEqual(frames[2]["declared_locals"], ["int"])

    def test_chop_frame(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x04)              # 0 iconst_1
        a.op(0x3B)              # 1 istore_0
        a.op(0x05)              # 2 iconst_2
        a.op(0x3C)              # 3 istore_1
        a.op(0x03)              # 4 iconst_0
        a.branch(0x99, "l1")    # 5 ifeq l1
        a.op(0x1A)              # 8 iload_0
        a.op(0x57)              # 9 pop
        a.branch(0xA7, "j")     # 10 goto j
        a.label("l1")           # 13
        a.op(0x00)              # 13 nop
        a.label("j")            # 14
        a.op(0x1B)              # 14 iload_1
        a.op(0x57)              # 15 pop
        a.op(0xB1)              # 16 return
        code = a.build()
        sm = (Sm()
              .append(a.labels["l1"], [vt_int(), vt_int()])  # @13 [int, int]
              .chop(a.labels["j"] - a.labels["l1"] - 1, 1))  # @14 [int]
        b.add_method("run", code, max_stack=1, max_locals=2,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        frames = res["stackmap"]["frames"]
        self.assertEqual(frames[1]["frame_type"], "chop")
        self.assertEqual(frames[1]["declared_locals"], ["int"])
        # the chopped-away slot is implicitly top, which covers derived int
        self.assertEqual(frames[1]["locals"], ["int", "int"])

    def test_full_frame_uninitialized_matches_derived(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x4B)              # 3 astore_0
        a.op(0x03)              # 4 iconst_0
        a.branch(0x99, "j")     # 5 ifeq j
        a.branch(0xA7, "j")     # 8 goto j
        a.label("j")            # 11
        a.op(0x2A)              # 11 aload_0
        a.op(0xB7).u2(init)     # 12 invokespecial <init>
        a.op(0xB1)              # 15 return
        code = a.build()
        sm = Sm().full(a.labels["j"], [vt_uninit(0)], [])
        b.add_method("run", code, max_stack=1, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        f = res["stackmap"]["frames"][0]
        self.assertEqual(f["declared_locals"], [f"uninit(new@0 {DIAG})"])
        self.assertEqual(f["locals"], [f"uninit(new@0 {DIAG})"])

    def test_null_and_reference_coverage(self):
        # declared Null matches derived null; declared Object also covers it
        for vti, expect in ((vt_null(), "null"), (None, f"ref {DIAG}")):
            with self.subTest(expect=expect):
                b, x, _init = diag_builder()
                a = Asm()
                a.op(0x01)              # 0 aconst_null
                a.op(0x4B)              # 1 astore_0
                a.branch(0xA7, "j")     # 2 goto j
                a.label("j")            # 5
                a.op(0x2A)              # 5 aload_0
                a.op(0x57)              # 6 pop
                a.op(0xB1)              # 7 return
                code = a.build()
                sm = Sm().full(a.labels["j"],
                               [vti if vti is not None else vt_object(x)],
                               [])
                b.add_method("run", code, max_stack=1, max_locals=1,
                             stackmap=sm.build())
                res = verify_class(b.build(), check_stackmap=True)
                self.assertTrue(res["ok"], res.get("error"))
                f = res["stackmap"]["frames"][0]
                self.assertEqual(f["declared_locals"], [expect])
                self.assertEqual(f["locals"], ["null"])

    def test_declared_top_covers_anything(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.op(0x3B)              # 1 istore_0
        a.branch(0xA7, "j")     # 2 goto j
        a.label("j")            # 5
        a.op(0xB1)              # 5 return
        code = a.build()
        sm = Sm().full(a.labels["j"], [vt_top()], [])
        b.add_method("run", code, max_stack=1, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))

    def test_unreachable_declared_frame_accepted(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0xB1)              # 0 return
        a.op(0x00)              # 1 nop (unreachable)
        code = a.build()
        sm = Sm().same(1)       # declares a frame at the unreachable nop
        b.add_method("run", code, max_stack=0, max_locals=0,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        f = res["stackmap"]["frames"][0]
        self.assertFalse(f["reachable"])
        self.assertIsNone(f["locals"])
        self.assertIsNone(f["stack"])


class DeclaredFrameRejectTests(unittest.TestCase):
    def test_declared_int_does_not_cover_derived_null(self):
        res = verify_class(stackmap_mismatch_class(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertEqual(res["error"]["offset"], 5)
        self.assertIn("local 0", res["error"]["message"])
        # the mismatch is reported together with the derived evidence
        self.assertEqual(len(res["stackmap"]["frames"]), 1)

    def test_declared_int_does_not_cover_derived_top(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA7, "j")     # 0 goto j
        a.label("j")            # 3
        a.op(0xB1)              # 3 return
        code = a.build()
        sm = Sm().full(a.labels["j"], [vt_int()], [])
        b.add_method("run", code, max_stack=0, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertEqual(res["error"]["offset"], 3)

    def test_uninitialized_mismatch_after_init(self):
        # construction completed -> the new@0 identity was replaced by the
        # initialized reference, so a declared Uninitialized(0) no longer
        # matches the derived state.
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.branch(0xA7, "j")     # 8 goto j
        a.label("j")            # 11
        a.op(0x2A)              # 11 aload_0
        a.op(0x57)              # 12 pop
        a.op(0xB1)              # 13 return
        code = a.build()
        sm = Sm().full(a.labels["j"], [vt_uninit(0)], [])
        b.add_method("run", code, max_stack=2, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertEqual(res["error"]["offset"], 11)
        self.assertIn("uninit(new@0", res["error"]["message"])

    def test_stack_height_mismatch(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0xA7, "j")     # 1 goto j
        a.label("j")            # 4
        a.op(0x3B)              # 4 istore_0
        a.op(0xB1)              # 5 return
        code = a.build()
        sm = Sm().same(a.labels["j"])   # declares an empty stack; derived [int]
        b.add_method("run", code, max_stack=1, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertEqual(res["error"]["offset"], 4)
        self.assertIn("stack", res["error"]["message"])

    def test_frame_into_instruction_middle(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA7, "end")   # 0 goto end
        a.op(0x11)              # 3 sipush ...
        a.u2(0x1234)            # 4..5 (mid-instruction bytes)
        a.label("end")          # 6
        a.op(0x00)              # 6 nop
        a.op(0xB1)              # 7 return
        sm = Sm().same(4)       # expands into the middle of sipush
        b.add_method("run", a.build(), max_stack=1, max_locals=0,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-offset")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.stackmap_body_off"] + 2)
        self.assertIn("offset 4", res["error"]["message"])

    def test_frame_target_beyond_code(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=Sm().same(500).build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-offset")

    def test_truncated_table_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=u2(1) + b"\xff")  # full_frame tag, then nothing
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.stackmap_body_off"] + 3)

    def test_truncated_second_frame_rejected(self):
        b = ClassBuilder()
        # one valid same_frame, then the declared second frame is missing
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=u2(2) + b"\x00")
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")

    def test_bad_constant_index_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=1,
                     stackmap=Sm().full(0, [vt_object(250)], []).build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-constant-index")
        # body + count(2) + tag(1) + delta(2) + nlocals(2) + vti tag(1)
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.stackmap_body_off"] + 8)

    def test_uninitialized_offset_not_a_new(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x57)              # 7 pop
        a.op(0xB1)              # 8 return
        code = a.build()
        for bad_off in (1, 3):  # mid-instruction, and a non-new instruction
            with self.subTest(bad_off=bad_off):
                sm = Sm().full(0, [vt_uninit(bad_off)], [])
                b2 = ClassBuilder()
                b2.cp = b.cp
                b2.add_method("run", code, max_stack=2, max_locals=1,
                              stackmap=sm.build())
                res = verify_class(b2.build(), check_stackmap=True)
                self.assertFalse(res["ok"])
                self.assertEqual(res["error"]["kind"],
                                 "bad-uninitialized-offset")
                self.assertIn(f"offset {bad_off}",
                              res["error"]["message"])

    def test_unknown_frame_tag_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=u2(1) + bytes([200]))
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unknown-stackmap-frame")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.stackmap_body_off"] + 2)

    def test_unknown_and_unsupported_verification_types(self):
        cases = [(b"\x09", "unknown-verification-type"),
                 (b"\x03", "unsupported-verification-type"),   # Long
                 (b"\x04", "unsupported-verification-type"),   # Double
                 (b"\x06", "unsupported-verification-type")]   # UninitThis
        for vti, kind in cases:
            with self.subTest(kind=kind):
                b = ClassBuilder()
                b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=1,
                             stackmap=Sm().full(0, [vti], []).build())
                res = verify_class(b.build(), check_stackmap=True)
                self.assertFalse(res["ok"])
                self.assertEqual(res["error"]["kind"], kind)

    def test_chop_underflow_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.op(0x3B)              # 1 istore_0
        a.op(0x00)              # 2 nop
        a.op(0xB1)              # 3 return
        code = a.build()
        sm = (Sm()
              .append(2, [vt_int()])   # @2 locals [int]
              .chop(0, 2))             # @3 removes 2, only 1 present
        b.add_method("run", code, max_stack=1, max_locals=1,
                     stackmap=sm.build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-frame")

    def test_locals_exceed_max_locals_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=1,
                     stackmap=Sm().append(0, [vt_int(), vt_int()]).build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-frame")

    def test_base_failure_takes_precedence_over_stackmap(self):
        # the method itself already fails verification; the (valid) declared
        # frame must not mask that first, stable evidence
        b = ClassBuilder()
        b.add_method("run", bytes([0x60, 0xB1]), max_stack=2, max_locals=0,
                     stackmap=Sm().same(0).build())
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-underflow")


if __name__ == "__main__":
    unittest.main()
