"""JVM type-state verifier for static ()V methods.

Implements a work-queue data-flow verifier in the spirit of the classic JVM
type-inference verifier, over a deliberately small instruction set:

  * constants / loads / stores (int + reference), iinc, iadd & friends
  * branches (if*, goto, goto_w)
  * object creation: new, dup, invokespecial <init>
  * athrow, return, and the Code exception table

Uninitialized objects are tracked by the identity (bytecode offset) of the
`new` instruction that created them.  Before <init> completes they must not
cross an exception edge into a handler, nor merge with initialized references
or with uninitialized instances of a different identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from heapq import heappop, heappush

from .classfile import ClassFile, ClassFormatError, MethodInfo, parse_class

ACC_STATIC = 0x0008

DEFAULT_MAX_STEPS = 200_000


class VerifyError(Exception):
    def __init__(self, offset: int, kind: str, message: str):
        self.offset = offset
        self.kind = kind
        self.message = message
        super().__init__(f"offset {offset}: {kind}: {message}")


# ---------------------------------------------------------------------------
# Verification types
# ---------------------------------------------------------------------------

TOP = ("top",)        # unusable local slot (never written, or merged-away)
INT = ("int",)
FLOAT = ("float",)
NULL = ("null",)


def REF(name):
    return ("ref", name)


def UNINIT(offset, cls):
    return ("uninit", offset, cls)


def is_uninit(t):
    return t[0] == "uninit"


def is_reflike(t):
    return t[0] in ("ref", "null")


def fmt(t) -> str:
    tag = t[0]
    if tag == "top":
        return "top"
    if tag in ("int", "float", "null"):
        return tag
    if tag == "ref":
        return f"ref {t[1]}"
    if tag == "uninit":
        return f"uninit(new@{t[1]} {t[2]})"
    return str(t)


def merge_types(a, b):
    """Merge two types; returns the merged type or None if incompatible."""
    if a == b:
        return a
    if a == TOP or b == TOP:
        return TOP
    if a == NULL and b[0] == "ref":
        return b
    if b == NULL and a[0] == "ref":
        return a
    if a[0] == "ref" and b[0] == "ref":
        # No class hierarchy is available (single class, no field/method
        # resolution); java/lang/Object is a sound common supertype.
        return a if a[1] == b[1] else REF("java/lang/Object")
    # uninitialized objects merge only with an identical identity (handled
    # by the a == b case above); anything else is incompatible.
    return None


@dataclass(frozen=True)
class Frame:
    locals: tuple
    stack: tuple


def merge_frames(fa: Frame, fb: Frame, offset: int) -> Frame:
    if len(fa.stack) != len(fb.stack):
        raise VerifyError(
            offset, "stack-height-mismatch",
            f"operand stack heights differ at control-flow join: "
            f"{len(fa.stack)} vs {len(fb.stack)}")
    locals_out = []
    for i, (x, y) in enumerate(zip(fa.locals, fb.locals)):
        m = merge_types(x, y)
        if m is None:
            raise VerifyError(
                offset, "incompatible-types",
                f"local {i} has incompatible types at control-flow join: "
                f"{fmt(x)} vs {fmt(y)}")
        locals_out.append(m)
    stack_out = []
    for i, (x, y) in enumerate(zip(fa.stack, fb.stack)):
        m = merge_types(x, y)
        if m is None:
            raise VerifyError(
                offset, "incompatible-types",
                f"operand stack slot {i} has incompatible types at "
                f"control-flow join: {fmt(x)} vs {fmt(y)}")
        stack_out.append(m)
    return Frame(tuple(locals_out), tuple(stack_out))


# ---------------------------------------------------------------------------
# Instruction decoding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Insn:
    offset: int
    op: int
    name: str
    operands: tuple
    size: int


_SIMPLE = {
    0x00: "nop", 0x01: "aconst_null",
    0x02: "iconst_m1", 0x03: "iconst_0", 0x04: "iconst_1", 0x05: "iconst_2",
    0x06: "iconst_3", 0x07: "iconst_4", 0x08: "iconst_5",
    0x1A: "iload_0", 0x1B: "iload_1", 0x1C: "iload_2", 0x1D: "iload_3",
    0x2A: "aload_0", 0x2B: "aload_1", 0x2C: "aload_2", 0x2D: "aload_3",
    0x3B: "istore_0", 0x3C: "istore_1", 0x3D: "istore_2", 0x3E: "istore_3",
    0x4B: "astore_0", 0x4C: "astore_1", 0x4D: "astore_2", 0x4E: "astore_3",
    0x57: "pop", 0x59: "dup",
    0x60: "iadd", 0x64: "isub", 0x68: "imul", 0x6C: "idiv", 0x70: "irem",
    0x74: "ineg", 0x78: "ishl", 0x7A: "ishr", 0x7C: "iushr",
    0x7E: "iand", 0x80: "ior", 0x82: "ixor",
    0xB1: "return", 0xBF: "athrow",
}

_FORMATS = {
    0x10: ("bipush", "b"), 0x11: ("sipush", "s2"),
    0x12: ("ldc", "cp1"), 0x13: ("ldc_w", "cp2"), 0x14: ("ldc2_w", "cp2"),
    0x15: ("iload", "u1"), 0x19: ("aload", "u1"),
    0x36: ("istore", "u1"), 0x3A: ("astore", "u1"),
    0x84: ("iinc", "iinc"),
    0x99: ("ifeq", "br2"), 0x9A: ("ifne", "br2"), 0x9B: ("iflt", "br2"),
    0x9C: ("ifge", "br2"), 0x9D: ("ifgt", "br2"), 0x9E: ("ifle", "br2"),
    0x9F: ("if_icmpeq", "br2"), 0xA0: ("if_icmpne", "br2"),
    0xA1: ("if_icmplt", "br2"), 0xA2: ("if_icmpge", "br2"),
    0xA3: ("if_icmpgt", "br2"), 0xA4: ("if_icmple", "br2"),
    0xA5: ("if_acmpeq", "br2"), 0xA6: ("if_acmpne", "br2"),
    0xA7: ("goto", "br2"),
    0xB7: ("invokespecial", "cp2"), 0xBB: ("new", "cp2"),
    0xC6: ("ifnull", "br2"), 0xC7: ("ifnonnull", "br2"),
    0xC8: ("goto_w", "br4"),
}

_SIZES = {"b": 2, "u1": 2, "s2": 3, "cp1": 2, "cp2": 3, "iinc": 3,
          "br2": 3, "br4": 5}


def decode(code: bytes) -> dict:
    """Linear-sweep decode; every offset in `code` is covered exactly once."""
    insns = {}
    n = len(code)
    off = 0
    while off < n:
        op = code[off]
        if op in _SIMPLE:
            insns[off] = Insn(off, op, _SIMPLE[op], (), 1)
            off += 1
            continue
        spec = _FORMATS.get(op)
        if spec is None:
            raise VerifyError(
                off, "unknown-opcode",
                f"opcode 0x{op:02x} is outside the supported instruction set")
        name, kind = spec
        size = _SIZES[kind]
        if off + size > n:
            raise VerifyError(
                off, "truncated-instruction",
                f"instruction {name} at offset {off} needs {size} byte(s), "
                f"only {n - off} remain in the code array")
        if kind == "b":
            operands = (int.from_bytes(code[off + 1:off + 2], "big",
                                       signed=True),)
        elif kind in ("u1", "cp1"):
            operands = (code[off + 1],)
        elif kind in ("s2", "br2"):
            operands = (int.from_bytes(code[off + 1:off + 3], "big",
                                       signed=True),)
        elif kind == "cp2":
            operands = (int.from_bytes(code[off + 1:off + 3], "big"),)
        elif kind == "br4":
            operands = (int.from_bytes(code[off + 1:off + 5], "big",
                                       signed=True),)
        elif kind == "iinc":
            operands = (code[off + 1],
                        int.from_bytes(code[off + 2:off + 3], "big",
                                       signed=True))
        insns[off] = Insn(off, op, name, operands, size)
        off += size
    return insns


# ---------------------------------------------------------------------------
# Constant pool helpers (verification phase; errors located at the use site)
# ---------------------------------------------------------------------------

def cp_entry(cf: ClassFile, idx: int, pc: int, what: str):
    if not (0 < idx < len(cf.cp.entries)) or cf.cp.entries[idx] is None:
        raise VerifyError(pc, "bad-constant-index",
                          f"constant pool index {idx} ({what}) is invalid")
    return cf.cp.entries[idx]


def cp_utf8(cf: ClassFile, idx: int, pc: int, what: str) -> str:
    e = cp_entry(cf, idx, pc, what)
    if e[0] != "Utf8":
        raise VerifyError(pc, "bad-constant-index",
                          f"constant pool index {idx} ({what}) must be Utf8, "
                          f"found {e[0]}")
    return e[1]


def cp_class_name(cf: ClassFile, idx: int, pc: int) -> str:
    e = cp_entry(cf, idx, pc, "class")
    if e[0] != "Class":
        raise VerifyError(pc, "bad-constant-index",
                          f"constant pool index {idx} must be a Class entry, "
                          f"found {e[0]}")
    return cp_utf8(cf, e[1], pc, "class name")


def cp_methodref(cf: ClassFile, idx: int, pc: int):
    e = cp_entry(cf, idx, pc, "method reference")
    if e[0] not in ("Methodref", "InterfaceMethodref"):
        raise VerifyError(pc, "bad-constant-index",
                          f"constant pool index {idx} must be a Methodref, "
                          f"found {e[0]}")
    cls = cp_class_name(cf, e[1], pc)
    nat = cp_entry(cf, e[2], pc, "name and type")
    if nat[0] != "NameAndType":
        raise VerifyError(pc, "bad-constant-index",
                          f"constant pool index {e[2]} must be a NameAndType "
                          f"entry, found {nat[0]}")
    name = cp_utf8(cf, nat[1], pc, "method name")
    desc = cp_utf8(cf, nat[2], pc, "method descriptor")
    return cls, name, desc


def parse_field_type(desc: str, i: int, pc: int):
    if i >= len(desc):
        raise VerifyError(pc, "bad-descriptor",
                          f'descriptor "{desc}" ends unexpectedly')
    c = desc[i]
    if c in "ZBCSI":
        return INT, i + 1
    if c == "F":
        return FLOAT, i + 1
    if c in "JD":
        raise VerifyError(pc, "unsupported-descriptor",
                          f'descriptor "{desc}" uses long/double, which is '
                          f"outside the supported scope")
    if c == "L":
        j = desc.find(";", i)
        if j < 0:
            raise VerifyError(pc, "bad-descriptor",
                              f'unterminated object type in "{desc}"')
        return REF(desc[i + 1:j]), j + 1
    if c == "[":
        j = i
        while j < len(desc) and desc[j] == "[":
            j += 1
        _, k = parse_field_type(desc, j, pc)
        return REF(desc[i:k]), k  # arrays are opaque references here
    raise VerifyError(pc, "bad-descriptor",
                      f'bad type "{c}" in descriptor "{desc}"')


def parse_method_descriptor(desc: str, pc: int):
    if not desc.startswith("("):
        raise VerifyError(pc, "bad-descriptor",
                          f'not a method descriptor: "{desc}"')
    args = []
    i = 1
    while i < len(desc) and desc[i] != ")":
        t, i = parse_field_type(desc, i, pc)
        args.append(t)
    if i >= len(desc):
        raise VerifyError(pc, "bad-descriptor",
                          f'unterminated parameter list in "{desc}"')
    i += 1
    if i < len(desc) and desc[i] == "V":
        ret = None
        i += 1
    else:
        ret, i = parse_field_type(desc, i, pc)
    if i != len(desc):
        raise VerifyError(pc, "bad-descriptor",
                          f'trailing characters in descriptor "{desc}"')
    return args, ret


# ---------------------------------------------------------------------------
# Disassembly (for the review page)
# ---------------------------------------------------------------------------

def disasm(insn: Insn, cf: ClassFile) -> str:
    n = insn.name
    try:
        if n.startswith("if") or n in ("goto", "goto_w"):
            return f"{n} {insn.offset + insn.operands[0]}"
        if n in ("bipush", "sipush"):
            return f"{n} {insn.operands[0]}"
        if n in ("iload", "aload", "istore", "astore"):
            return f"{n} {insn.operands[0]}"
        if n == "iinc":
            return f"iinc {insn.operands[0]} {insn.operands[1]}"
        if n in ("ldc", "ldc_w", "ldc2_w"):
            return f"{n} {_const_text(cf, insn.operands[0])}"
        if n == "new":
            return f"new {cp_class_name(cf, insn.operands[0], insn.offset)}"
        if n == "invokespecial":
            cls, name, desc = cp_methodref(cf, insn.operands[0], insn.offset)
            return f"invokespecial {cls}.{name}{desc}"
    except VerifyError:
        return f"{n} #{insn.operands[0]}"
    return n


def _const_text(cf: ClassFile, idx: int) -> str:
    e = cf.cp.entries[idx] if 0 < idx < len(cf.cp.entries) else None
    if e is None:
        return f"#{idx}"
    if e[0] == "Integer":
        return str(e[1])
    if e[0] == "String":
        s = cf.cp.entries[e[1]]
        return f'"{s[1]}"' if s and s[0] == "Utf8" else f"#{idx}"
    if e[0] == "Class":
        s = cf.cp.entries[e[1]]
        return f"class {s[1]}" if s and s[0] == "Utf8" else f"#{idx}"
    return f"{e[0]} #{idx}"


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------

class MethodVerifier:
    def __init__(self, cf: ClassFile, method: MethodInfo,
                 max_steps: int = DEFAULT_MAX_STEPS):
        self.cf = cf
        self.method = method
        self.code_attr = method.code
        self.max_steps = max_steps
        self.frames: dict[int, Frame] = {}
        self.insns: dict[int, Insn] = {}
        self.insns = decode(self.code_attr.code)
        self._validate_exception_table()

    def _validate_exception_table(self) -> None:
        code_len = len(self.code_attr.code)
        for e in self.code_attr.exceptions:
            ok = (0 <= e.start_pc < e.end_pc
                  and e.end_pc <= code_len
                  and e.start_pc in self.insns
                  and (e.end_pc == code_len or e.end_pc in self.insns)
                  and e.handler_pc in self.insns)
            if not ok:
                raise VerifyError(
                    e.table_offset, "bad-handler-range",
                    f"exception table entry (start_pc={e.start_pc}, "
                    f"end_pc={e.end_pc}, handler_pc={e.handler_pc}) is "
                    f"invalid for a code array of length {code_len}: "
                    f"start_pc and handler_pc must be instruction starts, "
                    f"end_pc must be an instruction start or code_length, "
                    f"and start_pc < end_pc")

    def run(self) -> "MethodVerifier":
        ca = self.code_attr
        if not self.insns:
            raise VerifyError(ca.attr_offset, "empty-code",
                              "method has an empty code array")
        self.frames[0] = Frame((TOP,) * ca.max_locals, ())
        work = [0]
        steps = 0
        while work:
            pc = heappop(work)
            steps += 1
            if steps > self.max_steps:
                raise VerifyError(
                    pc, "non-converging",
                    f"type state did not converge within {self.max_steps} "
                    f"analysis steps")
            frame = self.frames[pc]
            insn = self.insns[pc]
            # Exception edges: an exception raised by this instruction
            # empties the operand stack and keeps the local variables.
            for e in ca.exceptions:
                if e.start_pc <= pc < e.end_pc:
                    for i, t in enumerate(frame.locals):
                        if is_uninit(t):
                            raise VerifyError(
                                pc, "uninitialized-escapes-to-handler",
                                f"local {i} holds the uninitialized object "
                                f"created by new@{t[1]} ({t[2]}); the "
                                f"exception edge to handler@{e.handler_pc} "
                                f"would carry it into the handler before "
                                f"<init> completed")
                    catch = (REF("java/lang/Throwable") if e.catch_type == 0
                             else REF(cp_class_name(self.cf, e.catch_type, pc)))
                    self._offer(work, e.handler_pc,
                                Frame(frame.locals, (catch,)))
            for target, nframe in self._successors(pc, insn, frame):
                self._offer(work, target, nframe)
        return self

    def _offer(self, work: list, target: int, nframe: Frame) -> None:
        old = self.frames.get(target)
        if old is None:
            self.frames[target] = nframe
            heappush(work, target)
        else:
            merged = merge_frames(old, nframe, target)
            if merged != old:
                self.frames[target] = merged
                heappush(work, target)

    # -- instruction semantics -------------------------------------------

    def _successors(self, pc: int, insn: Insn, frame: Frame):
        n = insn.name
        ca = self.code_attr
        locals_ = list(frame.locals)
        stack = list(frame.stack)

        def err(kind, msg):
            raise VerifyError(pc, kind, msg)

        def pop():
            if not stack:
                err("stack-underflow",
                    f"{n} needs an operand but the operand stack is empty")
            return stack.pop()

        def push(t):
            stack.append(t)
            if len(stack) > ca.max_stack:
                err("stack-overflow",
                    f"{n} grows the operand stack to {len(stack)}, "
                    f"max_stack is {ca.max_stack}")

        def pop_int():
            t = pop()
            if t != INT:
                err("type-mismatch", f"{n} expects int, found {fmt(t)}")

        def pop_ref():
            t = pop()
            if is_uninit(t):
                err("uninitialized-object-used",
                    f"{n} cannot use the uninitialized object created by "
                    f"new@{t[1]} ({t[2]})")
            if not is_reflike(t):
                err("type-mismatch",
                    f"{n} expects a reference, found {fmt(t)}")
            return t

        def load(i):
            if i >= ca.max_locals:
                err("local-index-out-of-range",
                    f"{n} uses local {i} but max_locals is {ca.max_locals}")
            return locals_[i]

        def store(i, t):
            if i >= ca.max_locals:
                err("local-index-out-of-range",
                    f"{n} uses local {i} but max_locals is {ca.max_locals}")
            locals_[i] = t

        def fall():
            nxt = pc + insn.size
            if nxt >= len(ca.code):
                err("fall-off-end",
                    f"{n} falls through past the end of the code array")
            return nxt

        def branch_target():
            t = pc + insn.operands[0]
            if t not in self.insns:
                err("bad-branch-target",
                    f"{n} targets offset {t}, which is not the start of an "
                    f"instruction")
            return t

        def out():
            return Frame(tuple(locals_), tuple(stack))

        def via_fall():
            return [(fall(), out())]

        def via_branch():
            f = out()
            return [(branch_target(), f), (fall(), f)]

        # -- constants
        if n == "nop":
            return via_fall()
        if n == "aconst_null":
            push(NULL)
            return via_fall()
        if n.startswith("iconst") or n in ("bipush", "sipush"):
            push(INT)
            return via_fall()
        if n in ("ldc", "ldc_w"):
            e = cp_entry(self.cf, insn.operands[0], pc, "ldc constant")
            if e[0] == "Integer":
                push(INT)
            elif e[0] == "Float":
                push(FLOAT)
            elif e[0] == "String":
                push(REF("java/lang/String"))
            elif e[0] == "Class":
                push(REF("java/lang/Class"))
            else:
                err("unsupported-constant",
                    f"ldc of a {e[0]} constant is not supported")
            return via_fall()
        if n == "ldc2_w":
            err("unsupported-constant",
                "long/double constants are outside the supported scope")

        # -- loads / stores
        if n.startswith("iload"):
            i = insn.operands[0] if insn.operands else int(n[-1])
            if load(i) != INT:
                err("type-mismatch",
                    f"iload expects local {i} to be int, found "
                    f"{fmt(locals_[i])}")
            push(INT)
            return via_fall()
        if n.startswith("aload"):
            i = insn.operands[0] if insn.operands else int(n[-1])
            t = load(i)
            if not (is_reflike(t) or is_uninit(t)):
                err("type-mismatch",
                    f"aload expects local {i} to be a reference, found "
                    f"{fmt(t)}")
            push(t)
            return via_fall()
        if n.startswith("istore"):
            i = insn.operands[0] if insn.operands else int(n[-1])
            pop_int()
            store(i, INT)
            return via_fall()
        if n.startswith("astore"):
            i = insn.operands[0] if insn.operands else int(n[-1])
            t = pop()
            if not (is_reflike(t) or is_uninit(t)):
                err("type-mismatch",
                    f"astore expects a reference, found {fmt(t)}")
            store(i, t)
            return via_fall()
        if n == "iinc":
            if load(insn.operands[0]) != INT:
                err("type-mismatch",
                    f"iinc expects local {insn.operands[0]} to be int, found "
                    f"{fmt(locals_[insn.operands[0]])}")
            return via_fall()

        # -- stack manipulation
        if n == "pop":
            pop()
            return via_fall()
        if n == "dup":
            t = pop()
            push(t)
            push(t)
            return via_fall()

        # -- int arithmetic
        if n in ("iadd", "isub", "imul", "idiv", "irem", "ishl", "ishr",
                 "iushr", "iand", "ior", "ixor"):
            pop_int()
            pop_int()
            push(INT)
            return via_fall()
        if n == "ineg":
            pop_int()
            push(INT)
            return via_fall()

        # -- branches
        if n in ("ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle"):
            pop_int()
            return via_branch()
        if n.startswith("if_icmp"):
            pop_int()
            pop_int()
            return via_branch()
        if n.startswith("if_acmp"):
            pop_ref()
            pop_ref()
            return via_branch()
        if n in ("ifnull", "ifnonnull"):
            pop_ref()
            return via_branch()
        if n in ("goto", "goto_w"):
            return [(branch_target(), out())]

        # -- object creation / initialization
        if n == "new":
            cls = cp_class_name(self.cf, insn.operands[0], pc)
            push(UNINIT(pc, cls))
            return via_fall()
        if n == "invokespecial":
            cls, name, desc = cp_methodref(self.cf, insn.operands[0], pc)
            if name != "<init>":
                err("unsupported-invokespecial",
                    f"only constructors may be invoked here, found "
                    f"{cls}.{name}{desc}")
            args, ret = parse_method_descriptor(desc, pc)
            if ret is not None:
                err("bad-descriptor", f"<init> must return void: {desc}")
            for a in reversed(args):
                if a == INT:
                    pop_int()
                elif a == FLOAT:
                    if pop() != FLOAT:
                        err("type-mismatch", f"<init> expects a float argument")
                else:
                    pop_ref()
            obj = pop()
            if is_uninit(obj):
                if obj[2] != cls:
                    err("type-mismatch",
                        f"{cls}.<init> cannot initialize an instance of "
                        f"{obj[2]}")
                off = obj[1]
                repl = REF(cls)
                locals_ = [repl if (is_uninit(t) and t[1] == off
                                    and t[2] == cls) else t
                           for t in locals_]
                stack[:] = [repl if (is_uninit(t) and t[1] == off
                                     and t[2] == cls) else t
                            for t in stack]
            elif obj[0] == "ref":
                err("already-initialized",
                    f"invokespecial <init> targets an already initialized "
                    f"reference ({fmt(obj)})")
            else:
                err("type-mismatch",
                    f"invokespecial <init> expects an uninitialized object, "
                    f"found {fmt(obj)}")
            return via_fall()

        # -- method exit
        if n == "athrow":
            pop_ref()
            return []  # only exception edges continue from here
        if n == "return":
            return []

        err("unknown-opcode", f"unhandled instruction {n}")  # unreachable

    # -- result rendering --------------------------------------------------

    def states_json(self) -> list:
        out = []
        for off in sorted(self.insns):
            insn = self.insns[off]
            f = self.frames.get(off)
            out.append({
                "offset": off,
                "insn": disasm(insn, self.cf),
                "reachable": f is not None,
                "locals": [fmt(t) for t in f.locals] if f else None,
                "stack": [fmt(t) for t in f.stack] if f else None,
            })
        return out

    def handlers_json(self) -> list:
        out = []
        for e in self.code_attr.exceptions:
            f = self.frames.get(e.handler_pc)
            out.append({
                "start_pc": e.start_pc,
                "end_pc": e.end_pc,
                "handler_pc": e.handler_pc,
                "catch": self._catch_name(e),
                "table_offset": e.table_offset,
                "reachable": f is not None,
                "locals": [fmt(t) for t in f.locals] if f else None,
                "stack": [fmt(t) for t in f.stack] if f else None,
            })
        return out

    def _catch_name(self, e) -> str:
        if e.catch_type == 0:
            return "java/lang/Throwable"
        try:
            return cp_class_name(self.cf, e.catch_type, 0)
        except VerifyError:
            return f"#{e.catch_type}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _err(offset, kind, message, **extra):
    d = {"offset": offset, "kind": kind, "message": message}
    d.update(extra)
    return d


def verify_class(data: bytes, method_name: str | None = None,
                 max_steps: int = DEFAULT_MAX_STEPS) -> dict:
    """Verify one class file; always returns a result dict (never raises)."""
    base = {"ok": False, "method": method_name, "states": [], "handlers": []}
    try:
        cf = parse_class(data)
    except ClassFormatError as e:
        base["error"] = _err(e.offset, e.kind, e.message)
        return base
    base["class"] = cf.this_name

    candidates = [m for m in cf.methods
                  if (m.access & ACC_STATIC) and m.desc == "()V"]
    if method_name is not None:
        target = next((m for m in cf.methods if m.name == method_name), None)
        if target is None:
            base["error"] = _err(None, "no-target-method",
                                 f'class {cf.this_name} has no method named '
                                 f'"{method_name}"')
            return base
        if not (target.access & ACC_STATIC) or target.desc != "()V":
            base["error"] = _err(
                None, "no-target-method",
                f'method "{method_name}" is {"static " if target.access & ACC_STATIC else ""}'
                f"{target.desc}, not a static ()V method")
            return base
    else:
        if not candidates:
            base["error"] = _err(None, "no-target-method",
                                 f"class {cf.this_name} declares no static "
                                 f"()V method")
            return base
        if len(candidates) > 1:
            base["error"] = _err(
                None, "ambiguous-method",
                "class declares several static ()V methods; pick one via "
                'the "method" field',
                candidates=[m.name for m in candidates])
            return base
        target = candidates[0]

    base["method"] = target.name
    base["descriptor"] = target.desc
    if target.code is None:
        base["error"] = _err(None, "no-code",
                             f'method "{target.name}" has no Code attribute')
        return base
    base["max_stack"] = target.code.max_stack
    base["max_locals"] = target.code.max_locals

    v = None
    try:
        v = MethodVerifier(cf, target, max_steps)
        v.run()
    except VerifyError as e:
        base["error"] = _err(e.offset, e.kind, e.message)
        if v is not None:
            base["states"] = v.states_json()
            base["handlers"] = v.handlers_json()
        return base

    base["ok"] = True
    base["error"] = None
    base["states"] = v.states_json()
    base["handlers"] = v.handlers_json()
    return base
