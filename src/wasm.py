"""Minimal WASM binary decoder for the Prover.

Decodes the subset of WebAssembly that xahc-compiled Hooks use into a nested
instruction tree (block/loop/if carry their bodies), plus the import table so
`call N` resolves to a host-function name. Correctness is load-bearing — a wrong
decode means a wrong proof — so this is deliberately explicit and table-driven.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


class Reader:
    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def byte(self) -> int:
        v = self.b[self.i]
        self.i += 1
        return v

    def bytes(self, n: int) -> bytes:
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def uleb(self) -> int:
        r = 0
        s = 0
        while True:
            x = self.byte()
            r |= (x & 0x7F) << s
            s += 7
            if not (x & 0x80):
                return r

    def sleb(self) -> int:
        r = 0
        s = 0
        while True:
            x = self.byte()
            r |= (x & 0x7F) << s
            s += 7
            if not (x & 0x80):
                if x & 0x40:
                    r |= -(1 << s)
                return r

    def name(self) -> str:
        n = self.uleb()
        return self.bytes(n).decode("utf-8", "replace")

    def eof(self) -> bool:
        return self.i >= len(self.b)


@dataclass
class Instr:
    op: str
    # operands / immediates
    imm: Any = None        # const value, local/global idx, call name, memarg(offset)
    body: list = field(default_factory=list)        # block/loop/if-consequent
    alt: list = field(default_factory=list)         # if-else


@dataclass
class Func:
    name: str
    nlocals: int            # declared locals (after params)
    nparams: int
    body: list
    localtypes: list = field(default_factory=list)  # valtype byte per declared local
    paramtypes: list = field(default_factory=list)   # valtype byte per param
    nresults: int = 0       # number of result values the function returns


# opcode -> (mnemonic, immediate-kind)
# immediate-kind: '' none, 'u' uleb, 's' sleb32, 'S' sleb64, 'm' memarg, 'b' blocktype, 'c' call
OPS = {
    0x00: ("unreachable", ""), 0x01: ("nop", ""),
    0x02: ("block", "b"), 0x03: ("loop", "b"), 0x04: ("if", "b"),
    0x05: ("else", ""), 0x0B: ("end", ""),
    0x0C: ("br", "u"), 0x0D: ("br_if", "u"), 0x0E: ("br_table", "T"),
    0x0F: ("return", ""), 0x10: ("call", "u"), 0x11: ("call_indirect", "I"),
    0x1A: ("drop", ""), 0x1B: ("select", ""),
    0x20: ("local.get", "u"), 0x21: ("local.set", "u"), 0x22: ("local.tee", "u"),
    0x23: ("global.get", "u"), 0x24: ("global.set", "u"),
    0x28: ("i32.load", "m"), 0x29: ("i64.load", "m"),
    0x2C: ("i32.load8_s", "m"), 0x2D: ("i32.load8_u", "m"),
    0x2E: ("i32.load16_s", "m"), 0x2F: ("i32.load16_u", "m"),
    0x30: ("i64.load8_s", "m"), 0x31: ("i64.load8_u", "m"),
    0x32: ("i64.load16_s", "m"), 0x33: ("i64.load16_u", "m"),
    0x34: ("i64.load32_s", "m"), 0x35: ("i64.load32_u", "m"),
    0x36: ("i32.store", "m"), 0x37: ("i64.store", "m"),
    0x3A: ("i32.store8", "m"), 0x3B: ("i32.store16", "m"),
    0x3C: ("i64.store8", "m"), 0x3D: ("i64.store16", "m"), 0x3E: ("i64.store32", "m"),
    0x41: ("i32.const", "s"), 0x42: ("i64.const", "S"),
    0x45: ("i32.eqz", ""), 0x46: ("i32.eq", ""), 0x47: ("i32.ne", ""),
    0x48: ("i32.lt_s", ""), 0x49: ("i32.lt_u", ""), 0x4A: ("i32.gt_s", ""), 0x4B: ("i32.gt_u", ""),
    0x4C: ("i32.le_s", ""), 0x4D: ("i32.le_u", ""), 0x4E: ("i32.ge_s", ""), 0x4F: ("i32.ge_u", ""),
    0x50: ("i64.eqz", ""), 0x51: ("i64.eq", ""), 0x52: ("i64.ne", ""),
    0x53: ("i64.lt_s", ""), 0x54: ("i64.lt_u", ""), 0x55: ("i64.gt_s", ""), 0x56: ("i64.gt_u", ""),
    0x57: ("i64.le_s", ""), 0x58: ("i64.le_u", ""), 0x59: ("i64.ge_s", ""), 0x5A: ("i64.ge_u", ""),
    0x67: ("i32.clz", ""), 0x68: ("i32.ctz", ""), 0x69: ("i32.popcnt", ""),
    0x6A: ("i32.add", ""), 0x6B: ("i32.sub", ""), 0x6C: ("i32.mul", ""),
    0x6D: ("i32.div_s", ""), 0x6E: ("i32.div_u", ""), 0x6F: ("i32.rem_s", ""), 0x70: ("i32.rem_u", ""),
    0x71: ("i32.and", ""), 0x72: ("i32.or", ""), 0x73: ("i32.xor", ""),
    0x74: ("i32.shl", ""), 0x75: ("i32.shr_s", ""), 0x76: ("i32.shr_u", ""),
    0x77: ("i32.rotl", ""), 0x78: ("i32.rotr", ""),
    0x67: ("i32.clz", ""), 0x68: ("i32.ctz", ""), 0x69: ("i32.popcnt", ""),
    0x79: ("i64.clz", ""), 0x7A: ("i64.ctz", ""), 0x7B: ("i64.popcnt", ""),
    0x7C: ("i64.add", ""), 0x7D: ("i64.sub", ""), 0x7E: ("i64.mul", ""),
    0x7F: ("i64.div_s", ""), 0x80: ("i64.div_u", ""), 0x81: ("i64.rem_s", ""), 0x82: ("i64.rem_u", ""),
    0x83: ("i64.and", ""), 0x84: ("i64.or", ""), 0x85: ("i64.xor", ""),
    0x86: ("i64.shl", ""), 0x87: ("i64.shr_s", ""), 0x88: ("i64.shr_u", ""),
    0x89: ("i64.rotl", ""), 0x8A: ("i64.rotr", ""),
    0xA7: ("i32.wrap_i64", ""),
    0xAC: ("i64.extend_i32_s", ""), 0xAD: ("i64.extend_i32_u", ""),
}


def _memarg(r: Reader):
    align = r.uleb()
    offset = r.uleb()
    return offset


def _decode_seq(r: Reader, stop_on_else=False):
    """Decode an instruction sequence until matching `end` (or `else`).
    Returns (instrs, terminator) where terminator is 'end' or 'else'."""
    out = []
    while True:
        opc = r.byte()
        if opc not in OPS:
            raise NotImplementedError(f"opcode 0x{opc:02x} not supported by the prover decoder")
        mn, kind = OPS[opc]
        if mn == "end":
            return out, "end"
        if mn == "else":
            return out, "else"
        ins = Instr(mn)
        if mn in ("block", "loop", "if"):
            # Blocktype: one byte for the cases clang emits for hooks — 0x40 (void)
            # or a single valtype (0x7F i32 / 0x7E i64 / 0x7D f32 / 0x7C f64). The
            # spec also allows a *multi-value* blocktype encoded as a non-negative
            # sLEB128 type index, but clang does not emit those for hooks (no
            # multi-value results / params on these blocks). Guard defensively: a
            # leading byte with the high bit set would be a multi-byte sLEB type
            # index we don't model — fail loud rather than silently mis-align the
            # decode (a wrong decode means a wrong proof).
            bt = r.byte()
            if bt & 0x80:
                raise NotImplementedError(
                    f"multi-value blocktype (type index 0x{bt:02x}...) not supported "
                    f"by the prover decoder")
            body, term = _decode_seq(r)
            ins.body = body
            if mn == "if" and term == "else":
                alt, _ = _decode_seq(r)
                ins.alt = alt
        else:
            if kind == "u":
                ins.imm = r.uleb()
            elif kind == "s":
                ins.imm = r.sleb()
            elif kind == "S":
                ins.imm = r.sleb()
            elif kind == "m":
                ins.imm = _memarg(r)
            elif kind == "T":
                n = r.uleb()
                tgts = [r.uleb() for _ in range(n)]
                deflt = r.uleb()
                ins.imm = (tgts, deflt)
            elif kind == "I":
                # call_indirect: (type index, table index). KEEP the type index — the
                # engine type-checks each table entry against it (a mismatch traps).
                typeidx = r.uleb(); tableidx = r.uleb()  # tableidx is the 0x00 byte pre-reftypes
                ins.imm = (typeidx, tableidx)
        out.append(ins)


def parse(wasm: bytes):
    """Return (imports: list[str], funcs: list[Func]). Local funcs only in `funcs`;
    `call N` where N < len(imports) is a host call by imports[N]."""
    r = Reader(wasm)
    assert r.bytes(4) == b"\x00asm", "not a wasm module"
    r.bytes(4)  # version

    imports: list[str] = []
    func_type_idx: list[int] = []   # type index per local function
    type_sigs: list[tuple] = []     # (params, results)
    code_funcs: list[Func] = []
    datas: list[tuple] = []         # (offset, bytes) active data segments
    globals_init: list[tuple] = []  # (init_value, width_bits) per DEFINED global
    exports_fn: list[tuple] = []    # (name, func_idx) — applied after code is parsed
    import_func_count = 0
    import_type_idx: list[int] = [] # type index per imported function (call_indirect type-check)
    elems: dict = {}                # table_index -> global function index (active elements)
    elem_unsupported = False        # set if the element section uses constructs we don't decode

    while not r.eof():
        sid = r.byte()
        size = r.uleb()
        end = r.i + size
        if sid == 1:  # type
            n = r.uleb()
            for _ in range(n):
                assert r.byte() == 0x60
                np = r.uleb(); params = [r.byte() for _ in range(np)]
                nr = r.uleb(); results = [r.byte() for _ in range(nr)]
                type_sigs.append((params, results))
        elif sid == 2:  # import
            n = r.uleb()
            for _ in range(n):
                mod = r.name(); nm = r.name(); kind = r.byte()
                if kind == 0x00:  # func import
                    import_type_idx.append(r.uleb())  # type idx (kept for call_indirect check)
                    imports.append(nm)
                    import_func_count += 1
                elif kind == 0x01:  # table
                    r.byte(); flags = r.byte(); r.uleb()
                    if flags == 1: r.uleb()
                elif kind == 0x02:  # mem
                    flags = r.byte(); r.uleb()
                    if flags == 1: r.uleb()
                elif kind == 0x03:  # global
                    r.byte(); r.byte()
        elif sid == 3:  # function
            n = r.uleb()
            for _ in range(n):
                func_type_idx.append(r.uleb())
        elif sid == 6:  # global — DEFINED globals (init exprs). Hooks have no
            # imported globals, so defined-global index space starts at 0.
            n = r.uleb()
            for _ in range(n):
                vt = r.byte(); r.byte()  # valtype, mutability
                op = r.byte()
                if op in (0x41, 0x42):      # i32.const / i64.const
                    val = r.sleb()
                elif op == 0x23:            # global.get init (imported global) — rare
                    r.uleb(); val = 0
                else:
                    val = 0
                r.byte()  # 0x0b end
                w = 64 if vt in (0x7E, 0x7C) else 32
                globals_init.append((val, w))
        elif sid == 10:  # code
            n = r.uleb()
            for fi in range(n):
                fsize = r.uleb()
                fend = r.i + fsize
                nlocal_decls = r.uleb()
                nlocals = 0
                localtypes: list = []
                for _ in range(nlocal_decls):
                    cnt = r.uleb(); vt = r.byte()  # count, valtype
                    nlocals += cnt
                    localtypes += [vt] * cnt
                body, _ = _decode_seq(r)
                tparams, tresults = type_sigs[func_type_idx[fi]]
                code_funcs.append(Func(name="?", nparams=len(tparams), nlocals=nlocals,
                                       body=body, localtypes=localtypes, paramtypes=list(tparams),
                                       nresults=len(tresults)))
                r.i = fend
        elif sid == 11:  # data — active segments seed initial memory
            n = r.uleb()
            for _ in range(n):
                flags = r.uleb()
                if flags == 0:
                    # active, memory 0, offset = const expr
                    op = r.byte()  # 0x41 i32.const
                    off = r.sleb()
                    r.byte()  # 0x0b end
                    ln = r.uleb()
                    datas.append((off, r.bytes(ln)))
                elif flags == 1:
                    ln = r.uleb(); r.bytes(ln)  # passive, ignore
                else:
                    r.uleb()  # memidx
                    r.byte(); off = r.sleb(); r.byte()
                    ln = r.uleb()
                    datas.append((off, r.bytes(ln)))
        elif sid == 7:  # export — name the functions (hook/cbak) after code is parsed
            n = r.uleb()
            for _ in range(n):
                nm = r.name(); kind = r.byte(); idx = r.uleb()
                if kind == 0x00:
                    exports_fn.append((nm, idx))
        elif sid == 9:  # element — the function table call_indirect dispatches through.
            # We decode ONLY the simple active form clang emits for hooks: flag 0 =
            # (table 0, i32.const offset, vec(funcidx)). Anything else (passive,
            # declarative, table.init, expr-elements, non-zero table) is NOT guessed —
            # we mark the table unresolved so call_indirect fails closed to INCONCLUSIVE.
            n = r.uleb()
            for _ in range(n):
                flags = r.uleb()
                if flags != 0:
                    elem_unsupported = True
                    break
                op = r.byte()                       # offset const-expr
                if op != 0x41:                      # must be i32.const
                    elem_unsupported = True
                    break
                off = r.sleb()
                if r.byte() != 0x0B:                # end of const-expr
                    elem_unsupported = True
                    break
                m = r.uleb()
                for j in range(m):
                    elems[off + j] = r.uleb()       # table[off+j] = global func index
        r.i = end

    for nm, idx in exports_fn:
        if idx >= import_func_count:
            li = idx - import_func_count
            if li < len(code_funcs):
                code_funcs[li].name = nm

    # call_indirect dispatch data. `table` is the resolved {table_index -> global func
    # index} map, or None if the element section used constructs we don't decode (then
    # the engine fails closed to INCONCLUSIVE). The type tables let the engine type-check
    # each entry against the call_indirect type index (a mismatch traps).
    indirect = {
        "table": (None if elem_unsupported else elems),
        "import_count": import_func_count,
        "func_type_idx": func_type_idx,     # type idx per DEFINED func (key = local idx)
        "import_type_idx": import_type_idx,  # type idx per imported func
        "type_sigs": type_sigs,              # (params, results) tuple per type idx
    }
    return imports, code_funcs, datas, globals_init, indirect
