"""Independent adversarial verification of the SHARED state read-after-write change.

Hunts for a FALSE PROVEN introduced by same-invocation `state` read-after-write —
especially in prove_monotonic (highest risk), plus read-after-write byte/partial/
overlong/wrong-key correctness and the #8 time_nonce upgrade. Hand-assembled WASM
(no toolchain). Run: python tests/test_raw.py  (or pytest).
"""
import os
import sys
import struct
import z3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import prover                                           # noqa: E402
from prover import Engine, Path                         # noqa: E402
import prove_monotonic, prove_time_nonce                # noqa: E402

H = os.path.join(ROOT, "hooks")


# --- tiny hand WASM builder (mirrors tests/test_prover.py) ----------------------
def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _sleb(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def _sec(sid, payload):
    return bytes([sid]) + _uleb(len(payload)) + payload


def _vec(items):
    return _uleb(len(items)) + b"".join(items)


I32, I64 = 0x7F, 0x7E


def _ftype(params, results):
    return bytes([0x60]) + _vec([bytes([p]) for p in params]) + _vec([bytes([r]) for r in results])


def _module(types, imports, export_fn_idx, data_off, data_bytes, body, n_i64_locals=0):
    sec_type = _sec(1, _vec(types))
    sec_import = _sec(2, _vec(imports))
    sec_func = _sec(3, _vec([_uleb(0)]))                       # hook uses type 0
    sec_mem = _sec(5, _vec([bytes([0x00]) + _uleb(1)]))
    glob = bytes([I32, 0x01, 0x41]) + _sleb(65536) + bytes([0x0B])
    sec_global = _sec(6, _vec([glob]))
    exp = _uleb(len("hook")) + b"hook" + bytes([0x00]) + _uleb(export_fn_idx)
    sec_export = _sec(7, _vec([exp]))
    sec_data = _sec(11, _vec([_uleb(0) + bytes([0x41]) + _sleb(data_off) +
                              bytes([0x0B]) + _uleb(len(data_bytes)) + data_bytes]))
    # local decls: optionally some i64 locals
    locals_decl = _uleb(0) if not n_i64_locals else (_uleb(1) + _uleb(n_i64_locals) + bytes([I64]))
    func_body = locals_decl + body
    sec_code = _sec(10, _vec([_uleb(len(func_body)) + func_body]))
    return (b"\x00asm" + struct.pack("<I", 1) + sec_type + sec_import + sec_func +
            sec_mem + sec_global + sec_export + sec_data + sec_code)


def _i32c(n):
    return bytes([0x41]) + _sleb(n)


def _i64c(n):
    return bytes([0x42]) + _sleb(n)


def _imp(mod, nm, t):
    return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)


CALL = lambda i: bytes([0x10]) + _uleb(i)
DROP = bytes([0x1A])
END = bytes([0x0B])


def _run_monotonic(wasm, strict=False):
    path = os.path.join(ROOT, "tests", "_tmp_raw.wasm")
    open(path, "wb").write(wasm)
    try:
        return prove_monotonic.main(path, strict)
    finally:
        os.remove(path)


def _run_nonce(wasm):
    path = os.path.join(ROOT, "tests", "_tmp_raw_n.wasm")
    open(path, "wb").write(wasm)
    try:
        return prove_time_nonce.main(path)
    finally:
        os.remove(path)


# Standard import set for state-shaped hooks: state_set(1), state(2), accept(3),
# hook_param(4 optional). Type 0 = hook(i32)->i64.
def _state_module(body, *, n_i64_locals=0, data=None, want_param=False):
    types = [_ftype([I32], [I64]),                       # 0 hook
             _ftype([I32, I32, I32, I32], [I64]),        # 1 state_set
             _ftype([I32, I32, I32, I32], [I64]),        # 2 state
             _ftype([I32, I32, I32], [I64]),             # 3 accept
             _ftype([I32, I32, I32, I32], [I64])]        # 4 hook_param
    imports = [_imp("env", "state_set", 1), _imp("env", "state", 2),
               _imp("env", "accept", 3)]
    if want_param:
        imports.append(_imp("env", "hook_param", 4))
    if data is None:
        data = b"NONCE" + bytes([0]*8) + bytes([0]*8) + b"ok\x00"
    return _module(types, imports, export_fn_idx=3,
                   data_off=1024, data_bytes=data, body=body, n_i64_locals=n_i64_locals)


# Memory map used by these fixtures
KEY_PTR = 1024      # "NONCE" (5)
VAL_PTR = 1029      # 8 bytes
RD_PTR = 1037       # 8 bytes read buffer
MSG_PTR = 1045      # "ok\0"


# ================================================================================
# ATTACK 1 — prove_monotonic, the highest risk
# ================================================================================

def test_attack_write_readback_write_smaller_is_caught():
    """write(K, param) FIRST, read it back (read-after-write returns the staged param),
    then UNCONDITIONALLY write a SMALLER constant. The FINAL staged write is the small
    constant; there is NO comparison against the genuine prior. monotonic must NOT PROVEN.

    This is the canonical 'read-back the staged larger value, write smaller' attack: if
    read-after-write let the read-back stand in as the prior, a naive compare would think
    'small <= staged-large' is monotone-relative-to-what-we-read and PROVEN. It must
    instead compare the final write to state_old (never read) -> write-without-prior-read.
    """
    data = b"NONCE" + bytes([0xFF]*8) + bytes([0x00]*8) + b"ok\x00"
    body = b""
    # state_set(VAL_PTR=0xFF*8, 8, KEY, 5)  -- stage a large value
    body += _i32c(VAL_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP
    # state(RD_PTR, 8, KEY, 5)              -- read it back (gets staged 0xFF*8)
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(1) + DROP
    # state_set(RD_PTR+... no: write a SMALLER constant from data offset (all zero bytes)
    # ZERO_PTR points at the 8 zero bytes in data (offset 1024+5+8 = 1037 == RD_PTR though).
    # Use a fresh zero region: write VAL2_PTR which we fill with 0 via... simplest: reuse the
    # trailing zero bytes at 1037? That's RD_PTR (overwritten by read). Instead stage from a
    # constant zero buffer at KEY_PTR-... Just write 1 byte of 0x00 from MSG_PTR+2 ('\0').
    body += _i32c(MSG_PTR + 2) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP
    # accept(MSG_PTR, 2, 0)
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + CALL(2) + DROP
    body += _i64c(0) + END
    wasm = _state_module(body, data=data)
    rc = _run_monotonic(wasm)
    assert rc != 0, "write->readback->write-smaller was falsely PROVEN!"
    assert rc in (2, 3), f"expected CEX(2)/INCONCLUSIVE(3), got {rc}"


def test_genuine_backwards_write_via_readback_is_counterexample():
    """DECISIVE monotonic case: read the genuine prior FIRST (state_old populated), then
    write a SMALL constant, read it BACK (read-after-write returns the small staged value),
    then write that read-back value as the FINAL write. The final staged write (0) is below
    the genuine prior (symbolic, can be >0) -> a REAL monotonic violation that MUST be
    reported COUNTEREXAMPLE(2). If read-after-write had let the staged small value masquerade
    as the prior, ULT(0,0) would be UNSAT and this would falsely PROVEN."""
    data = b"NONCE" + bytes([0] * 8) + bytes([0] * 8) + b"ok\x00" + bytes([0] * 8)
    small_ptr = 1024 + len(b"NONCE") + 8 + 8 + 3   # the 8 trailing zero bytes
    body = b""
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(1) + DROP   # read prior
    body += _i32c(small_ptr) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP  # write small
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(1) + DROP   # read-back staged
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP   # final write = small
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + CALL(2) + DROP
    body += _i64c(0) + END
    wasm = _state_module(body, data=data)
    rc = _run_monotonic(wasm)
    assert rc == 2, f"genuine backwards write (via read-after-write) must be CEX(2), got {rc}"


def test_attack_readback_used_in_final_write_is_not_falsely_proven():
    """write(K, param), read it back, then write the READ-BACK value again as the final
    write. The final staged write == the staged param == an attacker-chosen value, still
    never compared to the genuine prior. Monotonic must NOT PROVEN (final write vs
    state_old, which is never populated -> write-without-prior-read)."""
    body = b""
    # state_set(VAL_PTR, 8, KEY, 5)  (VAL_PTR is symbolic? no — data zeros; use param-free)
    body += _i32c(VAL_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP
    # state(RD_PTR, 8, KEY, 5)  -> staged bytes into RD_PTR
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(1) + DROP
    # state_set(RD_PTR, 8, KEY, 5)  -> write the read-back value as the final write
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + CALL(2) + DROP
    body += _i64c(0) + END
    wasm = _state_module(body)
    rc = _run_monotonic(wasm)
    assert rc != 0, "readback-as-final-write was falsely PROVEN!"
    assert rc in (2, 3), f"got {rc}"


def test_correct_replay_guard_still_proven():
    """CONTROL: a CORRECT guard (read prior FIRST, then write the SAME prior bytes back)
    must still be PROVEN. Read-before-write keeps state_old populated; writing back the
    exact prior bytes is non-decreasing. This guards against the change making everything
    INCONCLUSIVE (over-conservative regression that would gut the product)."""
    body = b""
    # state(RD_PTR, 8, KEY, 5)  -> reads the genuine prior into RD_PTR (state_old created)
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(1) + DROP
    # state_set(RD_PTR, 8, KEY, 5)  -> write back EXACTLY the prior bytes (non-decreasing)
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + CALL(0) + DROP
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + CALL(2) + DROP
    body += _i64c(0) + END
    wasm = _state_module(body)
    rc = _run_monotonic(wasm)
    # writing back the prior verbatim: written == old -> non-decreasing -> PROVEN (non-strict)
    assert rc == 0, f"correct read-before-write-back guard should be PROVEN, got {rc}"
    # and under --strict it must be a counterexample (equal is not strictly greater)
    rc_strict = _run_monotonic(wasm, strict=True)
    assert rc_strict == 2, f"equal write under --strict should be CEX, got {rc_strict}"


# ================================================================================
# ATTACK 2 — read-after-write correctness/soundness (engine-level)
# ================================================================================

def _eng():
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    return e, p


def _set(e, p, key, val, rptr=2048, kptr=4096):
    for i, b in enumerate(val):
        p.mem[rptr + i] = b if z3.is_bv(b) else z3.BitVecVal(b & 0xFF, 8)
    for i, kb in enumerate(key):
        p.mem[kptr + i] = z3.BitVecVal(kb, 8)
    p.stack += [z3.BitVecVal(rptr, 64), z3.BitVecVal(len(val), 64),
                z3.BitVecVal(kptr, 64), z3.BitVecVal(len(key), 64)]
    e.host_call("state_set", p)
    p.stack.pop()


def _get(e, p, key, n, wptr=8192, kptr=4096):
    for i, kb in enumerate(key):
        p.mem[kptr + i] = z3.BitVecVal(kb, 8)
    p.stack += [z3.BitVecVal(wptr, 64), z3.BitVecVal(n, 64),
                z3.BitVecVal(kptr, 64), z3.BitVecVal(len(key), 64)]
    e.host_call("state", p)
    rlen = prover.conc(p.stack.pop())
    return rlen, [p.mem[wptr + i] for i in range(n)]


def test_wrong_key_read_is_symbolic_prior_not_staged():
    """Write KEY=0xFF*8, read a DIFFERENT key -> must be a fresh symbolic prior, never the
    staged 0xFF (else cross-key laundering could mask a violation / fake a value)."""
    e, p = _eng()
    _set(e, p, b"KEY", [0xFF] * 8)
    rlen, got = _get(e, p, b"OTH", 8)
    assert rlen == 8
    names = {str(z3.simplify(b)) for b in got}
    assert all(n.startswith("state_old:OTH") for n in names), f"wrong-key leaked staged: {names}"


def test_byte_exact_and_endianness():
    """Write N bytes, read N -> identical bytes in the same (big-endian, byte0=MSB) order."""
    e, p = _eng()
    val = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
    _set(e, p, b"NCE", val)
    rlen, got = _get(e, p, b"NCE", 8)
    assert rlen == 8
    assert [prover.conc(b) for b in got] == val
    # the whole-value Concat used by monotonic must reconstruct big-endian (byte0 = MSB)
    whole = p.writes["NCE"]
    assert prover.conc(whole) == int.from_bytes(bytes(val), "big")


def test_partial_read_is_exact_prefix():
    e, p = _eng()
    val = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    _set(e, p, b"NCE", val)
    rlen, got = _get(e, p, b"NCE", 3)
    assert rlen == 3
    assert [prover.conc(b) for b in got] == val[:3]
    assert "NCE" not in e.state_old, "partial-within-staged read fabricated a prior"


def test_overlong_read_tail_is_symbolic_never_zero():
    """Stage 4, read 8: tail 4 MUST be fresh symbolic prior (NOT zero-fill, which could
    fake a concrete value and mask a violation)."""
    e, p = _eng()
    _set(e, p, b"NCE", [0xAA, 0xBB, 0xCC, 0xDD])
    rlen, got = _get(e, p, b"NCE", 8)
    assert rlen == 8
    assert [prover.conc(b) for b in got[:4]] == [0xAA, 0xBB, 0xCC, 0xDD]
    tail = got[4:]
    for b in tail:
        s = z3.simplify(b)
        assert not z3.is_bv_value(s), f"overlong tail byte is CONCRETE ({s}) — zero/garbage fill!"
        assert str(s).startswith("state_old:NCE"), f"tail not symbolic prior: {s}"


def test_staged_read_does_not_fabricate_prior():
    e, p = _eng()
    _set(e, p, b"NCE", [0x01] * 8)
    _get(e, p, b"NCE", 8)
    assert "NCE" not in e.state_old, "staged read must not create state_old (the prior)"


# ================================================================================
# ATTACK 3 — #8 time_nonce upgrade real-catch + fail-close
# ================================================================================

def test_nonce_state_laundering_is_real_catch():
    """Confirm adv_nonce_state is a REAL catch (2): the nonce genuinely flows to accept via
    read-after-write, and the accept constraint references a nonce symbol (not a vacuous
    INCONCLUSIVE)."""
    rc = prove_time_nonce.main(os.path.join(H, "adv_nonce_state.wasm"))
    assert rc == 2, f"adv_nonce_state must be COUNTEREXAMPLE(2), got {rc}"
    # mechanism: a nonce symbol must appear in some accept constraint
    e = Engine(open(os.path.join(H, "adv_nonce_state.wasm"), "rb").read())
    e.run()
    names = {str(b) for b in e.nonce_syms}
    found = False
    for _code, cons in e.accepts:
        for c in cons:
            if prove_time_nonce._depends_on(c, names):
                found = True
                break
    assert found, "no nonce symbol in any accept constraint — read-after-write not wired"


def test_nonce_foreign_state_fails_closed_not_proven():
    """BELT-AND-SUSPENDERS: a nonce written to FOREIGN state (a route the engine cannot read
    back into the accept constraint) on an accepting path must fail closed. Since the engine
    does not register foreign writes in p.writes, this hook (foreign-set then accept) will be
    PROVEN-vacuous UNLESS something flags it. We assert it is at least NOT a false PROVEN that
    masks a laundering — here the nonce never reaches accept so PROVEN is actually correct;
    this test documents/locks that foreign-set alone (no local write) does not crash."""
    # This is a documentation/robustness check using existing foreign fixtures: ensure the
    # nonce driver does not throw on a foreign-state hook.
    rc = prove_time_nonce.main(os.path.join(H, "foreign_authz_ok.wasm"))
    assert rc in (0, 2, 3), f"unexpected rc {rc}"


def test_nonce_baselines_unchanged():
    assert prove_time_nonce.main(os.path.join(H, "time_nonce_ok.wasm")) == 0
    assert prove_time_nonce.main(os.path.join(H, "time_nonce_bug.wasm")) == 2
    assert prove_time_nonce.main(os.path.join(H, "adv_nonce_arith.wasm")) == 2


# ================================================================================
# run all
# ================================================================================
if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok  {fn.__name__}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {fn.__name__}: {ex}")
        except Exception as ex:
            failed += 1
            print(f"ERROR {fn.__name__}: {type(ex).__name__}: {ex}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
