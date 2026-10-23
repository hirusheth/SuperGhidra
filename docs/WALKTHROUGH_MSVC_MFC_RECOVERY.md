# 2-Minute End-to-End Walkthrough: MSVC RTTI, MFC `Serialize()` & Guardrailed Overlay Sync

This guide walks through a complete reverse-engineering loop on a Windows PE/COFF binary compiled with MSVC and MFC:
1. Recovering C++ RTTI class hierarchies, virtual function tables, and `CArchive` serialization layouts without starting Ghidra or a JVM.
2. Validating candidate class and method renames through `ReconstructionObligationLedger` so invalid offsets or vtable slot mismatches are rejected before commit.
3. Applying verified renames and struct layouts to an open Ghidra CodeBrowser window via `overlay-sync --watch` or merging headlessly via `merge_fork`.

---

## Step 1: Recover MSVC RTTI & MFC `Serialize()` Layouts (Standalone Python)

Run the standalone PE/COFF analyzers directly against your target binary (`target.dll` or `app.exe`) to extract `TypeDescriptor`, `CompleteObjectLocator`, `ClassHierarchyDescriptor`, MFC `CRuntimeClass` entries (`m_lpszClassName`, `m_nObjectSize`, `m_wSchema`), and `Cobject::Serialize(CArchive&)` field read/write sequences.

```bash
# 1. Recover C++ RTTI class hierarchy, base classes, and vtable RVAs
superghidra rtti-recover target.dll -o classes.json

# 2. Inspect detailed MFC CRuntimeClass descriptors and vtables
python -m superghidra.formats.msvc_class_recovery target.dll

# 3. Trace CArchive::operator<< / operator>> field layouts inside Serialize()
python -m superghidra.formats.serialize_trace target.dll CMyDoc
```

### Example Output (`classes.json` & `serialize_trace`)

`superghidra rtti-recover` writes a structured JSON map of recovered classes and vtable RVAs:

```json
{
  "CMyDoc": {
    "vtable_rvas": ["0x28410"],
    "methods_count": 14,
    "base_classes": ["CDocument", "CCmdTarget", "CObject"],
    "has_rtti": true
  }
}
```

`serialize_trace` walks `CMyDoc::Serialize(CArchive&)` across branches (`Ar.IsStoring()` vs. `Ar.IsLoading()`) and reports ordered field offsets, widths, and archive operations:

```text
Class: CMyDoc (schema=0x0002, object_size=0x68, vtable_slot=2 -> 0x180014200)
  [LOAD/STORE mirrored=True]
  +0x20: u32      ArchiveOp(op='>>', width=4, target_offset=0x20)  # m_dwVersionFlags
  +0x24: u32      ArchiveOp(op='>>', width=4, target_offset=0x24)  # m_nRecordCount
  +0x28: cstring  ArchiveOp(op='>>', width=8, target_offset=0x28)  # m_strHeaderTitle
  +0x30: f64      ArchiveOp(op='>>', width=8, target_offset=0x30)  # m_dScaleFactor
```

---

## Step 2: Validate Candidate Renames via `ReconstructionObligationLedger`

When an MCP agent (`recover_cpp_classes`, `trace_serialize`, `rename_function`, `set_variable_type`) or a script proposes applying these recovered names and field offsets to a Ghidra project, SuperGhidra does not write directly to the `.rep` database.

Instead, two safety mechanisms run:
1. **`ReconstructionObligationLedger` Verification:** Checks the candidate mutation against three structural verifiers (`VTableSlotVerifier`, `FieldDisplacementVerifier`, and `AllocationSizeVerifier`). If an agent hallucinates an unaligned vtable offset, an overlapping struct field, or a struct size larger than the constructor allocation (`operator new(0x68)`), the ledger marks the obligation `REJECTED` and raises `LedgerVerificationError` on commit.
2. **Read-Only Project + Write Overlay:** Accepted mutations are appended to `ghidra_overlay.json` (and `.ghidra-delta.jsonl`) while the underlying Ghidra `.rep` remains open in `readOnly=True` mode.

```python
from superghidra.core.evidence_ledger import (
    ObligationType,
    ReconstructionObligationLedger,
)
from superghidra.core.ghidra_oracle import WriteOverlay
from superghidra.diff.semantic_delta_log import DeltaOpType, SemanticDeltaLog

ledger = ReconstructionObligationLedger("evidence_ledger.json")
overlay = WriteOverlay("ghidra_overlay.json")
delta_log = SemanticDeltaLog(".ghidra-delta.jsonl")

# 1. Propose renaming sub_180014200 -> CMyDoc__Serialize with structural evidence
obl = ledger.propose(
    obligation_type=ObligationType.FUNCTION_RENAME,
    target_name="sub_180014200",
    proposed_name="CMyDoc__Serialize",
    target_address=0x180014200,
    evidence={
        # VTableSlotVerifier: slot 2 == offset 0x10 (8-byte aligned on x86_64)
        "vtable_slot": 2,
        "vtable_offset": 0x10,
        "vtable_total_size": 0x70,
        # AllocationSizeVerifier: CRuntimeClass.m_nObjectSize == 0x68
        "struct_size": 0x68,
        "allocation_size": 0x68,
        "allocation_source": "CRuntimeClass::CreateObject",
        # FieldDisplacementVerifier: natural alignment & non-overlapping bounds
        "field_displacements": [
            {"name": "m_dwVersionFlags", "offset": 0x20, "access_size": 4},
            {"name": "m_nRecordCount", "offset": 0x24, "access_size": 4},
            {"name": "m_strHeaderTitle", "offset": 0x28, "access_size": 8},
            {"name": "m_dScaleFactor", "offset": 0x30, "access_size": 8},
        ],
    },
)

# 2. Run VTableSlotVerifier, AllocationSizeVerifier, and FieldDisplacementVerifier
assert ledger.verify(obl.obligation_id) is True

# 3. Commit verified rename to ghidra_overlay.json and .ghidra-delta.jsonl
def write_to_overlay(verified_obl):
    addr_hex = f"0x{verified_obl.target_address:x}"
    overlay.set_rename(addr_hex, verified_obl.proposed_name)
    overlay.set_comment(
        addr_hex,
        "Verified MFC Serialize(CArchive&) slot=2 size=0x68",
    )
    delta_log.append_event(
        DeltaOpType.FUNCTION_RENAME,
        target_rva=verified_obl.target_address - 0x180000000,
        old_val=verified_obl.target_name,
        new_val=verified_obl.proposed_name,
    )

ledger.commit(obl.obligation_id, action_callback=write_to_overlay)
```

---

## Step 3: Apply Mutations to Ghidra (Live GUI Watcher or Headless `merge_fork`)

Once `ghidra_overlay.json` or `.ghidra-delta.jsonl` contains verified mutations, you can apply them either live inside an open Ghidra CodeBrowser window or headlessly once the GUI is closed.

### Option A: Live CodeBrowser Sync (`superghidra overlay-sync --watch`)

Generate a Ghidra Python script that either applies the current overlay once or runs a background watcher loop inside CodeBrowser that polls `ghidra_overlay.json` and applies new renames, comments, and struct definitions in atomic `currentProgram.startTransaction(...)` batches:

```bash
# Preview a human-readable diff summary grouped by address
superghidra overlay-sync --overlay ghidra_overlay.json --diff

# Generate a live background watcher script (polls every 1000 ms)
superghidra overlay-sync --overlay ghidra_overlay.json --watch --poll-ms 1000 --out ghidra_gui_overlay_sync.py
```

To run inside Ghidra:
1. Open **Window → Script Manager** in your active CodeBrowser window.
2. Add the directory containing `ghidra_gui_overlay_sync.py` to your Script Directories.
3. Run `ghidra_gui_overlay_sync.py`. Your open CodeBrowser listing and Decompiler view update as the agent commits new verified symbols.

### Option B: Headless Fork Merge with Conflict Detection (`merge_fork`)

If your agent worked inside an isolated session fork (or you prefer merging after closing the Ghidra GUI), call the `merge_fork` MCP tool or Python API to replay the fork's transaction journal back into the main project with conflict detection:

```python
from superghidra.core.ghidra_oracle import GhidraOracleSession

session = GhidraOracleSession(
    project_dir="E:/re/projects",
    project_name="target_app",
    program_name="target.dll",
)

# Replay journal operations; detects address/symbol conflicts and cleans up fork when pending_ops == 0
merge_report = session.merge_fork(fork_id="agent-mfc-pass-01", auto_discard=True)
print(merge_report)
# {'status': 'merged', 'applied_ops': 18, 'conflicts': [], 'pending_ops': 0, 'discarded': True}
```
