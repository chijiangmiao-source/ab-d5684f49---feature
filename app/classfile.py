"""Minimal JVM class file parser: constant pool, methods and Code attributes.

Every structural problem is reported as ClassFormatError carrying the exact
byte offset in the class file where the problem was detected.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class ClassFormatError(Exception):
    def __init__(self, offset: int, kind: str, message: str):
        self.offset = offset
        self.kind = kind
        self.message = message
        super().__init__(f"offset {offset}: {kind}: {message}")


class Reader:
    """Bounds-checked big-endian reader.

    `end` may limit reading to a sub-region (e.g. a declared attribute body);
    reads past the limit raise ClassFormatError with `kind`.
    """

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None,
                 kind: str = "truncated"):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end
        self.kind = kind

    def _need(self, n: int, what: str) -> None:
        if self.pos + n > self.end:
            raise ClassFormatError(
                self.pos, self.kind,
                f"unexpected end of data while reading {what}: "
                f"need {n} byte(s) at offset {self.pos}, limit is {self.end}")

    def u1(self, what: str = "u1") -> int:
        self._need(1, what)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u2(self, what: str = "u2") -> int:
        self._need(2, what)
        v = (self.data[self.pos] << 8) | self.data[self.pos + 1]
        self.pos += 2
        return v

    def u4(self, what: str = "u4") -> int:
        self._need(4, what)
        v = int.from_bytes(self.data[self.pos:self.pos + 4], "big")
        self.pos += 4
        return v

    def take(self, n: int, what: str = "bytes") -> bytes:
        self._need(n, what)
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v


@dataclass
class CpInfo:
    entries: list  # 1-based; entries[0] is None; long/double take two slots

    def get(self, idx: int, what: str, offset: int):
        if not (0 < idx < len(self.entries)) or self.entries[idx] is None:
            raise ClassFormatError(
                offset, "bad-constant-index",
                f"constant pool index {idx} ({what}) is invalid")
        return self.entries[idx]

    def expect(self, idx: int, tag: str, what: str, offset: int):
        e = self.get(idx, what, offset)
        if e[0] != tag:
            raise ClassFormatError(
                offset, "bad-constant-index",
                f"constant pool index {idx} ({what}) must be a {tag} entry, "
                f"found {e[0]}")
        return e


@dataclass
class ExceptionEntry:
    start_pc: int
    end_pc: int
    handler_pc: int
    catch_type: int      # constant pool index, 0 = catch-all (finally)
    table_offset: int    # file offset of this 8-byte entry


@dataclass
class CodeAttr:
    max_stack: int
    max_locals: int
    code: bytes
    exceptions: list
    attr_offset: int     # file offset of the Code attribute


@dataclass
class MethodInfo:
    name: str
    desc: str
    access: int
    code: CodeAttr | None
    index: int


@dataclass
class ClassFile:
    minor: int
    major: int
    cp: CpInfo
    access: int
    this_name: str
    super_name: str | None
    methods: list


def _skip_attributes(r: Reader, cp: CpInfo, owner: str) -> None:
    for _ in range(r.u2(f"{owner} attributes_count")):
        aoff = r.pos
        aname = cp.expect(r.u2("attribute name_index"), "Utf8",
                          "attribute name", aoff)[1]
        alen = r.u4("attribute_length")
        if r.pos + alen > r.end:
            raise ClassFormatError(
                aoff, "truncated-attribute",
                f'attribute "{aname}" declares {alen} byte(s) but only '
                f"{r.end - r.pos} remain in the class file")
        r.take(alen, f'attribute "{aname}"')


def _parse_code(r: Reader, alen: int, astart: int, cp: CpInfo) -> CodeAttr:
    end = r.pos + alen
    sub = Reader(r.data, r.pos, end, kind="truncated-attribute")
    max_stack = sub.u2("Code.max_stack")
    max_locals = sub.u2("Code.max_locals")
    clen = sub.u4("Code.code_length")
    code = sub.take(clen, "Code.code")
    exceptions = []
    for _ in range(sub.u2("Code.exception_table_length")):
        eoff = sub.pos
        exceptions.append(ExceptionEntry(
            sub.u2("exception start_pc"), sub.u2("exception end_pc"),
            sub.u2("exception handler_pc"), sub.u2("exception catch_type"),
            eoff))
    for _ in range(sub.u2("Code.attributes_count")):
        soff = sub.pos
        sname = cp.expect(sub.u2("code attribute name_index"), "Utf8",
                          "code attribute name", soff)[1]
        slen = sub.u4("code attribute_length")
        if sub.pos + slen > sub.end:
            raise ClassFormatError(
                soff, "truncated-attribute",
                f'Code attribute "{sname}" declares {slen} byte(s) but only '
                f"{sub.end - sub.pos} remain inside the Code attribute")
        sub.take(slen, f'code attribute "{sname}"')
    if sub.pos != end:
        raise ClassFormatError(
            astart, "attribute-length-mismatch",
            f"Code attribute declares {alen} byte(s) but its content uses "
            f"{sub.pos - (end - alen)}")
    r.pos = end
    return CodeAttr(max_stack, max_locals, code, exceptions, astart)


def parse_class(data: bytes) -> ClassFile:
    r = Reader(data)
    magic = r.u4("magic")
    if magic != 0xCAFEBABE:
        raise ClassFormatError(0, "bad-magic",
                               f"not a JVM class file (magic 0x{magic:08x})")
    minor = r.u2("minor_version")
    major = r.u2("major_version")

    cp_count = r.u2("constant_pool_count")
    entries = [None]
    i = 1
    while i < cp_count:
        tag_off = r.pos
        tag = r.u1("constant pool tag")
        if tag == 1:    # Utf8
            n = r.u2("CONSTANT_Utf8 length")
            raw = r.take(n, "CONSTANT_Utf8 bytes")
            entries.append(("Utf8", raw.decode("utf-8", "replace")))
        elif tag == 3:  # Integer
            entries.append(("Integer", int.from_bytes(
                r.take(4, "CONSTANT_Integer"), "big", signed=True)))
        elif tag == 4:  # Float
            entries.append(("Float", r.take(4, "CONSTANT_Float")))
        elif tag == 5:  # Long
            entries.append(("Long", r.take(8, "CONSTANT_Long")))
            entries.append(None)
            i += 1
        elif tag == 6:  # Double
            entries.append(("Double", r.take(8, "CONSTANT_Double")))
            entries.append(None)
            i += 1
        elif tag == 7:  # Class
            entries.append(("Class", r.u2("CONSTANT_Class name_index")))
        elif tag == 8:  # String
            entries.append(("String", r.u2("CONSTANT_String string_index")))
        elif tag in (9, 10, 11):
            name = {9: "Fieldref", 10: "Methodref", 11: "InterfaceMethodref"}[tag]
            entries.append((name, r.u2(f"CONSTANT_{name} class_index"),
                            r.u2(f"CONSTANT_{name} name_and_type_index")))
        elif tag == 12:  # NameAndType
            entries.append(("NameAndType", r.u2("name_index"),
                            r.u2("descriptor_index")))
        elif tag == 15:  # MethodHandle
            entries.append(("MethodHandle", r.u1("reference_kind"),
                            r.u2("reference_index")))
        elif tag == 16:  # MethodType
            entries.append(("MethodType", r.u2("descriptor_index")))
        elif tag in (17, 18):
            name = "Dynamic" if tag == 17 else "InvokeDynamic"
            entries.append((name, r.u2("bootstrap_method_attr_index"),
                            r.u2("name_and_type_index")))
        elif tag == 19:
            entries.append(("Module", r.u2("name_index")))
        elif tag == 20:
            entries.append(("Package", r.u2("name_index")))
        else:
            raise ClassFormatError(tag_off, "unknown-cp-tag",
                                   f"unknown constant pool tag {tag}")
        i += 1
    cp = CpInfo(entries)

    access = r.u2("access_flags")
    off = r.pos
    this_idx = r.u2("this_class")
    this_name = cp.expect(
        cp.expect(this_idx, "Class", "this_class", off)[1],
        "Utf8", "this_class name", off)[1]
    off = r.pos
    super_idx = r.u2("super_class")
    super_name = None
    if super_idx != 0:
        super_name = cp.expect(
            cp.expect(super_idx, "Class", "super_class", off)[1],
            "Utf8", "super_class name", off)[1]

    for _ in range(r.u2("interfaces_count")):
        r.u2("interface")

    for _ in range(r.u2("fields_count")):
        r.u2("field access_flags")
        r.u2("field name_index")
        r.u2("field descriptor_index")
        _skip_attributes(r, cp, "field")

    methods = []
    for mi in range(r.u2("methods_count")):
        m_access = r.u2("method access_flags")
        noff = r.pos
        m_name = cp.expect(r.u2("method name_index"), "Utf8",
                           "method name", noff)[1]
        doff = r.pos
        m_desc = cp.expect(r.u2("method descriptor_index"), "Utf8",
                           "method descriptor", doff)[1]
        code = None
        for _ in range(r.u2("method attributes_count")):
            aoff = r.pos
            aname = cp.expect(r.u2("attribute name_index"), "Utf8",
                              "attribute name", aoff)[1]
            alen = r.u4("attribute_length")
            if r.pos + alen > r.end:
                raise ClassFormatError(
                    aoff, "truncated-attribute",
                    f'attribute "{aname}" declares {alen} byte(s) but only '
                    f"{r.end - r.pos} remain in the class file")
            if aname == "Code":
                code = _parse_code(r, alen, aoff, cp)
            else:
                r.take(alen, f'attribute "{aname}"')
        methods.append(MethodInfo(m_name, m_desc, m_access, code, mi))

    _skip_attributes(r, cp, "class")
    if r.pos != r.end:
        raise ClassFormatError(r.pos, "trailing-bytes",
                               f"{r.end - r.pos} trailing byte(s) after the "
                               f"class file structure")
    return ClassFile(minor, major, cp, access, this_name, super_name, methods)
