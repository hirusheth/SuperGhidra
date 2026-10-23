"""Tests for Hex-Rays defs.h compatibility header and deterministic 70/30 function-disjoint splits."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.humaneval_decompile.harness import (
    LENIENT_IDA_DEFS,
    compute_split_metrics,
    split_humaneval_corpus,
)
from superghidra.core.compilable_filter import (
    IDA_COMPAT_DEFS_H,
    CompilableDecompilerFilter,
)
from superghidra.core.native_compiler import c_compiler, compile_and_run

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _working_c_compiler() -> bool:
    if c_compiler() is None:
        return False
    ok, _, _ = compile_and_run("int main(void) { return 0; }")
    return bool(ok)


needs_cc = pytest.mark.skipif(
    not _working_c_compiler(),
    reason="no working C toolchain found",
)


def test_ida_compat_defs_h_contains_all_required_typedefs_and_macros() -> None:
    assert LENIENT_IDA_DEFS == IDA_COMPAT_DEFS_H

    required_typedefs = (
        "_BYTE",
        "_WORD",
        "_DWORD",
        "_QWORD",
        "_OWORD",
        "_BOOL1",
        "_BOOL2",
        "_BOOL4",
        "_BOOL8",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
        "_UNKNOWN",
    )
    for td in required_typedefs:
        assert td in IDA_COMPAT_DEFS_H, f"Missing typedef {td} in IDA_COMPAT_DEFS_H"

    required_macros = (
        "LOBYTE",
        "HIBYTE",
        "LOWORD",
        "HIWORD",
        "LODWORD",
        "HIDWORD",
        "BYTE1",
        "BYTE2",
        "BYTE3",
        "BYTE4",
        "BYTE5",
        "BYTE6",
        "BYTE7",
        "WORD1",
        "WORD2",
        "WORD3",
        "DWORD1",
        "DWORD2",
        "SLOBYTE",
        "SHIBYTE",
        "SLOWORD",
        "SHIWORD",
        "SLODWORD",
        "SHIDWORD",
        "__PAIR16__",
        "__PAIR32__",
        "__PAIR64__",
        "COERCE_FLOAT",
        "COERCE_DOUBLE",
        "COERCE_UNSIGNED_INT",
        "COERCE_UNSIGNED_INT64",
        "__CFADD__",
        "__OFSUB__",
        "__SETP__",
    )
    for macro in required_macros:
        assert macro in IDA_COMPAT_DEFS_H, f"Missing macro {macro} in IDA_COMPAT_DEFS_H"


def test_filter_strips_ida_annotations_and_injects_defs() -> None:
    raw_ida = (
        "//----- (0000000000401120) ----------------------------------------------------\n"
        "_QWORD __usercall compute_pair@<rax>(_DWORD a1@<edi>, _DWORD a2@<esi>) __spoils<rdx,rcx>\n"
        "{\n"
        "  _QWORD v3;\n"
        "  LODWORD(v3) = a1;\n"
        "  HIDWORD(v3) = a2;\n"
        "  return __PAIR64__(HIDWORD(v3), LOBYTE(v3));\n"
        "}\n"
    )
    filtered = CompilableDecompilerFilter.filter(raw_ida)
    assert "SUPERGHIDRA_IDA_COMPAT_DEFS_H" in filtered
    assert "__usercall" not in filtered
    assert "__spoils" not in filtered
    assert "@<rax>" not in filtered
    assert "@<edi>" not in filtered
    assert "//-----" not in filtered
    assert "_QWORD compute_pair(_DWORD a1, _DWORD a2)" in filtered


@needs_cc
def test_ida_pseudo_c_compiles_and_runs() -> None:
    raw_ida = (
        "//----- (0000000000401120) ----------------------------------------------------\n"
        "_QWORD __fastcall ida_kernel(_DWORD hi, _DWORD lo)\n"
        "{\n"
        "  _QWORD acc = 0;\n"
        "  LODWORD(acc) = lo;\n"
        "  HIDWORD(acc) = hi;\n"
        "  float one = COERCE_FLOAT(0x3F800000U);\n"
        "  _DWORD raw_one = COERCE_UNSIGNED_INT(one);\n"
        "  _BYTE b0 = LOBYTE(lo);\n"
        "  _BYTE b1 = BYTE1(lo);\n"
        "  _WORD w1 = HIWORD(lo);\n"
        "  _QWORD paired = __PAIR64__(HIDWORD(acc), LODWORD(acc));\n"
        "  int carry = __CFADD__(0xFFFFFFFFU, 1U);\n"
        "  int of = __OFSUB__(10, 20);\n"
        "  int par = __SETP__(3, 0);\n"
        "  if (raw_one != 0x3F800000U || carry != 1 || of != 0 || par != 1)\n"
        "    return 0;\n"
        "  return paired + b0 + b1 + w1;\n"
        "}\n"
    )
    filtered = CompilableDecompilerFilter.filter(raw_ida)
    program = (
        filtered
        + "\n#include <assert.h>\n"
        "int main(void) {\n"
        "  _QWORD res = ida_kernel(0x11223344U, 0x55667788U);\n"
        "  _QWORD expected = 0x1122334455667788ULL + 0x88U + 0x77U + 0x5566U;\n"
        "  assert(res == expected);\n"
        "  return 0;\n"
        "}\n"
    )
    ok, _out, err = compile_and_run(program, language="C")
    assert ok, f"Filtered IDA program failed to compile or run: {err}"


def test_split_humaneval_corpus_zero_function_leakage() -> None:
    synthetic_rows = []
    for func_idx in range(100):
        lang = "c" if func_idx < 50 else "cpp"
        fname = f"func_{func_idx}"
        fbody = f"int {fname}(int x) {{ return x + {func_idx}; }}"
        for opt_idx, opt in enumerate(("O0", "O1", "O2", "O3")):
            synthetic_rows.append(
                {
                    "index": func_idx * 4 + opt_idx,
                    "func_name": fname,
                    "func": fbody,
                    "language": lang,
                    "opt": opt,
                    "ghidra_pseudo": fbody,
                    "test": f"int main(void) {{ return {fname}(0) - {func_idx}; }}",
                }
            )

    splits = split_humaneval_corpus(synthetic_rows, train_ratio=0.70, seed=42)
    train_rows = splits["train"]
    test_rows = splits["test"]
    o2_o3_rows = splits["o2_o3_test"]

    train_funcs = {(r["language"], r["func_name"]) for r in train_rows}
    test_funcs = {(r["language"], r["func_name"]) for r in test_rows}
    train_bodies = {(r["language"], r["func"].strip()) for r in train_rows}
    test_bodies = {(r["language"], r["func"].strip()) for r in test_rows}

    assert set(train_funcs) & set(test_funcs) == set()
    assert set(train_bodies) & set(test_bodies) == set()
    assert len(train_funcs) == 70
    assert len(test_funcs) == 30
    assert len(train_rows) == 280
    assert len(test_rows) == 120
    assert len(o2_o3_rows) == 60
    assert all(r["opt"] in ("O2", "O3") for r in o2_o3_rows)

    # Every function in train or test must have all 4 optimization levels together
    for split_rows in (train_rows, test_rows):
        opts_by_func: dict = {}
        for r in split_rows:
            opts_by_func.setdefault((r["language"], r["func_name"]), set()).add(r["opt"])
        for fk, opts in opts_by_func.items():
            assert opts == {"O0", "O1", "O2", "O3"}, f"Incomplete opts for {fk}: {opts}"

    # Verify on cached real humaneval.jsonl if present
    cache_jsonl = REPO_ROOT / "benchmarks" / "humaneval_decompile" / "cache" / "humaneval.jsonl"
    if cache_jsonl.is_file():
        real_rows = [
            json.loads(line)
            for line in cache_jsonl.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        real_splits = split_humaneval_corpus(real_rows, train_ratio=0.70, seed=42)
        real_train_bodies = {(r["language"], r["func"].strip()) for r in real_splits["train"]}
        real_test_bodies = {(r["language"], r["func"].strip()) for r in real_splits["test"]}
        assert real_train_bodies & real_test_bodies == set()
        assert len(real_train_bodies) == 230
        assert len(real_test_bodies) == 98
        assert len(real_splits["train"]) == 920
        assert len(real_splits["test"]) == 392
        assert len(real_splits["o2_o3_test"]) == 196


def test_compute_split_metrics_on_real_and_synthetic_logs() -> None:
    log_path = REPO_ROOT / "docs" / "benchmarks" / "humaneval" / "gcc_score_log_slim.jsonl"
    summary_path = REPO_ROOT / "docs" / "benchmarks" / "humaneval" / "gcc_score_summary.json"
    assert log_path.is_file()
    assert summary_path.is_file()

    score_rows = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    metrics = compute_split_metrics(score_rows, train_ratio=0.70, seed=42)

    assert metrics["total_unique_functions"] == 328
    assert metrics["train_unique_functions"] == 230
    assert metrics["test_unique_functions"] == 98

    full = metrics["full_corpus"]
    tr = metrics["train_split_70"]
    te = metrics["test_split_30"]
    o23 = metrics["test_o2_o3_high_opt"]

    assert full["evaluable_denominator"] == 1300
    assert tr["evaluable_denominator"] + te["evaluable_denominator"] == 1300
    assert tr["ghidra_filtered_pass_count"] + te["ghidra_filtered_pass_count"] == full["ghidra_filtered_pass_count"]
    assert tr["ida_raw_pass_count"] + te["ida_raw_pass_count"] == full["ida_raw_pass_count"]
    assert te["filter_broken_ghidra"] == 0
    assert te["filter_gained_ghidra"] == 55
    assert o23["evaluable_denominator"] == 194
    assert o23["filter_broken_ghidra"] == 0

    committed = json.loads(summary_path.read_text(encoding="utf-8"))
    assert committed["train_70"]["evaluable_denominator"] == tr["evaluable_denominator"]
    assert committed["test_30"]["evaluable_denominator"] == te["evaluable_denominator"]
    assert committed["test_30"]["ghidra_filtered_pass_count"] == te["ghidra_filtered_pass_count"]
    assert committed["test_o2_o3"]["ghidra_filtered_pass_count"] == o23["ghidra_filtered_pass_count"]
