"""Unit tests for declared-frame (StackMapTable) checking."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.verifier import verify_class  # noqa: E402
from builder import (Asm, ClassBuilder, u1, u2, legal_construction_class,  # noqa: E402
                     stackmap_mismatch_class, stackmap_pass_class,
                     uninitialized_escape_class)

DIAG = "com/acme/Diag"


def diag_builder():
    b = ClassBuilder()
    x = b.cp.cls(DIAG)
    init = b.cp.methodref(DIAG, "<init>", "()V")
    return b, x, init


def deltas(*offsets):
    """Absolute code offsets -> StackMapTable offset deltas."""
    out, prev = [], -1
    for o in offsets:
        out.append(o if prev < 0 else o - prev - 1)
        prev = o
    return out


class DeclaredFramePassTests(unittest.TestCase):
    def test_shared_fixture_passes(self):
        res = verify_class(stackmap_pass_class(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(len(res["stackmaps"]), 2)
        f1, f2 = res["stackmaps"]
        self.assertEqual((f1["kind"], f1["offset"]), ("append", 11))
        self.assertEqual(f1["locals"], [f"uninit(new@0 {DIAG})"])
        self.assertEqual(f1["derived_locals"], [f"uninit(new@0 {DIAG})"])
        self.assertEqual((f2["kind"], f2["offset"]), ("full", 20))
        self.assertEqual(f2["locals"], [f"ref {DIAG}"])
        self.assertEqual(f2["derived_locals"], [f"ref {DIAG}"])

    def test_append_same_and_chop_pass(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "j")     # 1 ifeq j
        a.op(0x04)              # 4 iconst_1
        a.op(0x3B)              # 5 istore_0
        a.branch(0xA7, "j")     # 6 goto j
        a.label("j")            # 9
        a.op(0x03)              # 9 iconst_0
        a.branch(0x99, "k")     # 10 ifeq k
        a.op(0xB1)              # 13 return
        a.label("k")            # 14
        a.op(0xB1)              # 14 return
        code = a.build()
        j, k = a.labels["j"], a.labels["k"]
        self.assertEqual((j, k), (9, 14))
        d1, d2, d3 = deltas(6, j, k)
        sm = b.smt(("append", d1, [("int",)]),   # at 6: locals [int]
                   ("same", d2),                 # at 9: locals stay [int]
                   ("chop", d3, 1))              # at 14: locals []
        b.add_method("run", code, max_stack=1, max_locals=1, stackmap=sm)
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        kinds = [f["kind"] for f in res["stackmaps"]]
        self.assertEqual(kinds, ["append", "same", "chop"])
        self.assertEqual([f["offset"] for f in res["stackmaps"]], [6, 9, 14])
        self.assertEqual(res["stackmaps"][1]["locals"], ["int"])
        self.assertEqual(res["stackmaps"][1]["derived_locals"], ["top"])
        self.assertEqual(res["stackmaps"][2]["locals"], [])

    def test_same_locals_1_stack_item_compact_and_extended(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x04)              # 0 iconst_1
        a.branch(0xA7, "j")     # 1 goto j
        a.label("j")            # 4
        a.op(0x05)              # 4 iconst_2
        a.op(0x57)              # 5 pop
        a.op(0x06)              # 6 iconst_3
        a.op(0x60)              # 7 iadd
        a.op(0x57)              # 8 pop
        a.op(0xB1)              # 9 return
        code = a.build()
        j = a.labels["j"]
        sm = b.smt(("same1", j, ("int",)),                 # compact (64+delta)
                   ("raw", u1(247) + u2(1) + u1(1)))       # extended, delta 1
        b.add_method("run", code, max_stack=2, max_locals=0, stackmap=sm)
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        f1, f2 = res["stackmaps"]
        self.assertEqual(f1["frame_type"], 64 + j)
        self.assertEqual(f1["stack"], ["int"])
        self.assertEqual(f1["derived_stack"], ["int"])
        self.assertEqual(f2["frame_type"], 247)
        self.assertEqual(f2["offset"], j + 2)  # second frame: prev + delta + 1
        self.assertEqual(f2["stack"], ["int"])

    def test_full_frame_and_extended_same_pass(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.op(0x01)              # 8 aconst_null
        a.op(0x4C)              # 9 astore_1
        a.branch(0xA7, "j")     # 10 goto j
        a.label("j")            # 13
        a.op(0x2A)              # 13 aload_0
        a.op(0x57)              # 14 pop
        a.op(0x03)              # 15 iconst_0
        a.branch(0x99, "k")     # 16 ifeq k
        a.op(0xB1)              # 19 return
        a.label("k")            # 20
        a.op(0xB1)              # 20 return
        code = a.build()
        j, k = a.labels["j"], a.labels["k"]
        d1, d2 = deltas(j, k)
        sm = b.smt(("full", d1, [("ref", DIAG), ("null",)], []),
                   ("raw", u1(251) + u2(d2)))  # same_frame_extended
        b.add_method("run", code, max_stack=2, max_locals=2, stackmap=sm)
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        f1, f2 = res["stackmaps"]
        self.assertEqual(f1["locals"], [f"ref {DIAG}", "null"])
        self.assertEqual(f1["derived_locals"], [f"ref {DIAG}", "null"])
        self.assertEqual(f2["frame_type"], 251)
        self.assertEqual(f2["locals"], [f"ref {DIAG}", "null"])

    def test_post_init_frame_must_use_initialized_reference(self):
        # After <init> the identity new@0 has been replaced by the
        # initialized reference; declaring it uninitialized is a mismatch.
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
        j = a.labels["j"]
        good = b.smt(("append", j, [("uninit", 0)]),
                     ("full", 15 - j - 1, [("ref", DIAG)], []))
        b.add_method("run", code, max_stack=1, max_locals=1, stackmap=good)
        res = verify_class(b.build(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["stackmaps"][1]["locals"], [f"ref {DIAG}"])

        b2, x2, init2 = diag_builder()
        bad = b2.smt(("append", j, [("uninit", 0)]),
                     ("full", 15 - j - 1, [("uninit", 0)], []))
        b2.add_method("run", code, max_stack=1, max_locals=1, stackmap=bad)
        res = verify_class(b2.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertIn("local 0", res["error"]["message"])

    def test_no_stackmap_attribute_passes_with_empty_list(self):
        res = verify_class(legal_construction_class(), check_stackmap=True)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["stackmaps"], [])

    def test_analysis_error_still_reported_first(self):
        res = verify_class(uninitialized_escape_class(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"],
                         "uninitialized-escapes-to-handler")
        self.assertNotIn("stackmaps", res)


class DeclaredFrameRejectionTests(unittest.TestCase):
    def _run(self, code, sm, max_stack=1, max_locals=1):
        b = ClassBuilder()
        b.add_method("run", code, max_stack=max_stack, max_locals=max_locals,
                     stackmap=sm)
        data = b.build()
        return verify_class(data, check_stackmap=True), b

    def test_frame_into_instruction_middle(self):
        # sipush occupies offsets 0..2; a frame at offset 1 lands inside it.
        code = bytes([0x11, 0x12, 0x34, 0x57, 0xB1])
        res, b = self._run(code, ClassBuilder().smt(("same", 1)))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-target")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2)
        self.assertIn("offset 1", res["error"]["message"])

    def test_frame_past_code_end(self):
        code = bytes([0xB1])
        res, _ = self._run(code, ClassBuilder().smt(("same", 7)))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-target")

    def test_truncated_frame_sequence(self):
        # Declares two frames but carries bytes for only one.
        code = bytes([0xB1])
        res, b = self._run(code, u2(2) + u1(0))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 3)

    def test_trailing_bytes_after_frames(self):
        code = bytes([0xB1])
        res, _ = self._run(code, u2(1) + u1(0) + u1(0))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "attribute-length-mismatch")

    def test_object_info_with_invalid_constant_pool_index(self):
        code = bytes([0xB1])
        sm = u2(1) + u1(255) + u2(0) + u2(1) + u1(7) + u2(999) + u2(0)
        res, b = self._run(code, sm)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-constant-index")
        # cpool_index sits at info + frame_type(1) + delta(2) + locals(2)
        # + tag(1) after the 2-byte entry count.
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2 + 1 + 2 + 2 + 1)

    def test_uninitialized_offset_not_a_new(self):
        code = bytes([0x03, 0x3B, 0xA7, 0x00, 0x03, 0x1A, 0x57, 0xB1])
        #          iconst_0  istore_0  goto +3 -> 5   iload_0 pop return
        res, b = self._run(code, ClassBuilder().smt(
            ("append", 5, [("uninit", 0)])))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-uninitialized")
        # the verification_type_info tag byte of the append frame's item
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2 + 1 + 2)
        self.assertIn("not a new instruction", res["error"]["message"])

    def test_type_conflict_with_derived_state(self):
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
        j = a.labels["j"]
        sm = b.smt(("full", j, [("int",)], []))
        b.add_method("run", code, max_stack=2, max_locals=1, stackmap=sm)
        data = b.build()
        res = verify_class(data, check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2)
        self.assertIn("local 0", res["error"]["message"])

    def test_shared_mismatch_fixture(self):
        res = verify_class(stackmap_mismatch_class(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        # the first frame was fine, so it remains as partial evidence
        self.assertEqual(len(res["stackmaps"]), 1)

    def test_stack_height_mismatch_with_derived_state(self):
        code = bytes([0x04, 0xA7, 0x00, 0x03, 0x05, 0x60, 0x57, 0xB1])
        #          iconst_1  goto +3 -> 4   iconst_2 iadd pop return
        res, _ = self._run(code, ClassBuilder().smt(("same", 4)),
                           max_stack=2, max_locals=0)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertIn("stack height", res["error"]["message"])

    def test_frame_at_unreachable_offset(self):
        code = bytes([0xA7, 0x00, 0x03, 0xB1, 0x03, 0x57, 0xB1])
        #          goto +3 -> 3   return  iconst_0(unreachable) pop return
        res, _ = self._run(code, ClassBuilder().smt(("same", 4)),
                           max_locals=0)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertIn("no reachable derived state",
                      res["error"]["message"])

    def test_compressed_frame_cannot_hide_live_local(self):
        # Declared frame omits local 1, but the derived state has a live
        # int there: the compressed frame is masking real state.
        code = bytes([0x04, 0x3B, 0x05, 0x3C, 0xA7, 0x00, 0x03,
                      0x1A, 0x57, 0xB1])
        #          iconst_1 istore_0 iconst_2 istore_1 goto +3 -> 7
        #          iload_0 pop return
        res, _ = self._run(code, ClassBuilder().smt(
            ("append", 7, [("int",)])), max_locals=2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stackmap-mismatch")
        self.assertIn("local 1", res["error"]["message"])

    def test_reserved_frame_type(self):
        code = bytes([0xB1])
        res, b = self._run(code, u2(1) + u1(200))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unknown-stackmap-frame")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2)

    def test_unsupported_verification_type(self):
        code = bytes([0xB1])
        sm = u2(1) + u1(255) + u2(0) + u2(1) + u1(3) + u2(0)  # Long local
        res, b = self._run(code, sm)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"],
                         "unsupported-verification-type")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2 + 1 + 2 + 2)

    def test_unknown_verification_type_tag(self):
        code = bytes([0xB1])
        sm = u2(1) + u1(255) + u2(0) + u2(1) + u1(9) + u2(0)
        res, _ = self._run(code, sm)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unknown-verification-type")

    def test_chop_underflow(self):
        code = bytes([0xB1])
        res, b = self._run(code, ClassBuilder().smt(("chop", 0, 1)))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-stackmap-chop")
        self.assertEqual(res["error"]["offset"],
                         b.marks["method0.smt_info_off"] + 2)


class ToggleCompatibilityTests(unittest.TestCase):
    def test_malformed_table_ignored_when_toggle_off(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=u2(2) + u1(0))  # truncated frame sequence
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertNotIn("stackmaps", res)

    def test_same_malformed_table_rejected_when_toggle_on(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0,
                     stackmap=u2(2) + u1(0))
        res = verify_class(b.build(), check_stackmap=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")

    def test_mismatch_class_passes_plain_verification(self):
        res = verify_class(stackmap_mismatch_class())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertNotIn("stackmaps", res)


if __name__ == "__main__":
    unittest.main()
