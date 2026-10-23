# SuperGhidra

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL_3.0--or--later-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/superghidra.svg)](https://pypi.org/project/superghidra/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org/)
[![CI](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml/badge.svg)](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml)

Python tools that make Ghidra faster to script against, plus a few analyses it doesn't do out of the box: MFC/C++ class recovery, `Serialize()` layout tracing, cross-version function matching, and a Z3 equivalence checker for P-code.

Instead of paying 5–15 seconds of JVM startup per headless run or fighting `.rep` project lock contention while the Ghidra GUI is open, SuperGhidra keeps a single read-only Ghidra instance warm in a background daemon (`127.0.0.1:5073`) backed by an L2 SQLite cache and a non-destructive JSON write overlay. Heavy binary sweeps and class-layout recovery run in pure Python, NumPy SIMD, or WGPU compute shaders without touching the JVM.

## Choose Your Operating Mode First

SuperGhidra spans four distinct execution paths. Pick the entry point that matches your task before running commands:

| What You Want to Do | Entry Point / Command | Requires Ghidra + JVM? | Writes to `.rep` Directly? |
| :--- | :--- | :---: | :---: |
| **Decompile real functions, query xrefs, or rename symbols** | `python ghidra_oracle.py <subcommand>` | **Yes** (Ghidra 11/12 + OpenJDK 21 + PyGhidra) | **No** (writes go to JSON overlay / fork journal) |
| **Recover MSVC RTTI, MFC `CRuntimeClass`, `Serialize()`, or PE/ELF/Mach-O headers** | `python -m superghidra.formats.msvc_class_recovery <binary>` or `superghidra rtti-recover <binary> -o classes.json` | **No** (standalone Python) | **No** (exports JSON, DWARF 5, Breakpad, or `.map`) |
| **Connect Claude Desktop, Cursor, or Antigravity to an open target** | MCP Server (`superghidra-mcp` via [SuperghidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)) | **Yes** (connects to running daemon) | **No** (commits gated by validation + overlay sync) |
| **Run GPU/SIMD ARM64 scans, LZ4/Zstd buffer compression, or Z3 P-code checks** | `superghidra <subcommand>` (Unified CLI) | **No** (standalone Python / NumPy / WGPU / Z3) | **No** |

> [!WARNING]
> **The `superghidra decompile` CLI Subcommand is Experimental**
>
> Do **not** use `superghidra decompile` to decompile production binaries. The standalone `superghidra decompile` CLI subcommand invokes an experimental, zero-JVM P-code lifter restricted to a small integer-arithmetic subset (register-to-register `mov`/`add`/`xor` and `ret` on x86-64; any other instruction exits non-zero). It will exit non-zero or return incomplete output on real functions containing branches, floats, or complex calls.
>
> **To decompile real functions from a Ghidra project, use the Ghidra-backed oracle:**
> ```bash
> python ghidra_oracle.py decompile <addr>
> ```

## Architecture & Zero Lock Contention

Ghidra locks `.rep` projects exclusively, meaning standard headless scripts fail whenever the project is open in the Ghidra GUI. SuperGhidra avoids lock contention by separating **reads** (served from a warm daemon or read-only session) from **writes** (recorded in a JSON overlay and transaction journal):

```
+-------------------------------------------------------------------+
| 1. READ PATH (Zero Lock Contention)                               |
|    [Ghidra .rep Fork / Read-Only Session]                         |
|           │                                                       |
|           ▼                                                       |
|    [SuperGhidra Daemon (127.0.0.1:5073)]                          |
|      ├── L1 Shared-Memory Ring Buffer (64 KB SHM, ~5.12 µs IPC)   |
|      └── L2 SQLite Query Cache (>100k req/s cached lookups)       |
+-------------------------------------------------------------------+
                              │
        Agent / Oracle Queries & Proposed Mutations
                              ▼
+-------------------------------------------------------------------+
| 2. VALIDATION & WRITE OVERLAY (Non-Destructive)                   |
|    [Naming & Struct Pipeline Gate]                                |
|      └── Verifies vtable slots, field offsets & allocation sizes  |
|           │                                                       |
|           ▼                                                       |
|    [JSON Write Overlay + Fork Journal]                            |
|      └── Stores renames, comments & types outside the main .rep   |
+-------------------------------------------------------------------+
                              │
             Sync Back to Main Project (Two Options)
              ┌────────────────┴────────────────┐
              ▼                                 ▼
+---------------------------+     +---------------------------------+
| 3A. LIVE GHIDRA GUI SYNC  |     | 3B. HEADLESS JOURNAL REPLAY     |
| Option 1: run script in   |     | Option 2: replay journal into   |
| Ghidra Script Manager:    |     | main .rep or merge session fork |
| superghidra overlay-sync  |     | via merge_fork                  |
| (ghidra_gui_overlay_sync) |     |                                 |
+---------------------------+     +---------------------------------+
```

## 5-Minute End-to-End Quickstart

### Workflow A: Standalone C++ / MSVC / MFC Class Recovery (No Ghidra Required)

Recover MSVC RTTI hierarchies, MFC `CRuntimeClass` descriptors, and virtual function tables directly from raw PE binaries without requiring Ghidra or a JVM:

```bash
# Direct module execution
python -m superghidra.formats.msvc_class_recovery target.dll

# Or recover classes and export to JSON via unified CLI
superghidra rtti-recover target.dll -o classes.json

# Trace MFC Serialize() archive field layouts
python -m superghidra.formats.serialize_trace target.dll CMyDoc
```

### Workflow B: Ghidra Daemon + Oracle Decompilation + GUI Sync

#### 1. Set Environment Variables
Point SuperGhidra to NSA Ghidra (11.x or 12.x) and OpenJDK 21:

```bash
# Linux / macOS
export GHIDRA_INSTALL_DIR="/opt/ghidra"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk"

# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra"
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21"
```

#### 2. Launch or Query the Persistent Daemon
Verify the daemon status or launch it with project coordinates:

```bash
# Check daemon status (auto-reports uptime, cache hit rate, and loaded binary)
python ghidra_oracle.py status

# Run daemon with explicit project paths
python ghidra_oracle.py --project-dir ~/re/proj --project-name game --program-name libgame.so status

# Or launch as a dedicated background server on port 5073
python ghidra_oracle.py serve --project-dir ~/re/proj --project-name game --program-name libgame.so --mode balanced
```

You can also define candidate projects globally via `SUPERGHIDRA_PROJECTS="dir,name[,program]"`.

#### 3. Decompile and Propose Renames
Subsequent queries execute in `< 0.01 ms` when served from the SQLite L2 cache:

```bash
# Decompile target function by virtual address
python ghidra_oracle.py decompile 0x140001000

# Propose function rename (committed safely to the JSON write overlay)
python ghidra_oracle.py rename 0x140001000 ProcessPacketHeader

# Add an address comment
python ghidra_oracle.py comment 0x140001000 "Validated packet parser entry point"
```

#### 4. Sync Overlay Back to Ghidra GUI
Mutations are recorded in `ghidra_overlay.json` to prevent `.rep` lock collisions. Sync them back into the Ghidra GUI session:

* **Option 1 — Live Ghidra GUI Sync (`ghidra_gui_overlay_sync.py`):**
  1. Generate the sync script:
     ```bash
     superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py
     ```
  2. In Ghidra's CodeBrowser, navigate to **Window $\rightarrow$ Script Manager**.
  3. Add the output directory to Script Paths and run `ghidra_gui_overlay_sync.py`. All renames, comments, and type definitions apply atomically inside your active GUI session.

* **Option 2 — Headless Journal Replay & Auto-Discard (`merge_fork`):**
  Close the project in the Ghidra GUI to release the `.rep` lock, then replay the journal or merge session forks using `merge_fork(fork_id, auto_discard=True)`.
  When `auto_discard=True`, once all operations merge cleanly with zero pending conflicts (`pending_ops == 0`), SuperGhidra automatically deletes the fork's isolated directory and transaction journal to reclaim disk storage. Unneeded or stale forks can also be deleted directly via `discard_fork(fork_id)`.

## Agent & MCP Configuration (Claude Desktop, Cursor, Antigravity)

SuperGhidra exposes 38 specialized reverse-engineering tools via the Model Context Protocol (MCP) using [SuperghidraMCP](https://github.com/yuatemycat/SuperGhidraMCP) (including `recover_cpp_classes`, `trace_serialize`, `diff_binaries`, `verify_smt_equivalence`, and `gpu_adrp_scan`). This enables AI coding agents to inspect binaries, query call graphs, and propose validated renames autonomously.

Install the MCP server from source:

```bash
pip install git+https://github.com/yuatemycat/SuperGhidraMCP.git
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "superghidra": {
      "command": "superghidra-mcp",
      "args": [
        "-t",
        "stdio",
        "--project-path",
        "<path_to_gpr_or_binary>"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

*Alternative using `uvx`:* Replace `"command": "superghidra-mcp"` with `"command": "uvx"` and set `"args"` to:
```json
["--from", "git+https://github.com/yuatemycat/SuperGhidraMCP.git", "superghidra-mcp", "-t", "stdio", "--project-path", "<path_to_gpr_or_binary>"]
```

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "superghidra": {
      "command": "superghidra-mcp",
      "args": [
        "-t",
        "stdio",
        "--project-path",
        "<path_to_gpr_or_binary>"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

### Antigravity / HTTP Transport

For remote daemon connections or HTTP-based agent configurations:

```bash
claude mcp add --transport http superghidra http://127.0.0.1:8000/mcp
```

Or configure via YAML:

```yaml
mcp_servers:
  superghidra:
    command: superghidra-mcp
    args:
      - "-t"
      - "stdio"
      - "--project-path"
      - "<path_to_gpr_or_binary>"
    env:
      GHIDRA_INSTALL_DIR: "/opt/ghidra"
      JAVA_HOME: "/path/to/jdk-21"
```

## Subsystem Capabilities & Hardware Matrix

| Package / Subsystem | What It Does | Hardware / Dependency Behavior |
| :--- | :--- | :--- |
| **`core` (Daemon & Cache)** | Persistent RPC server on `127.0.0.1:5073`, 64 KB shared-memory ring buffer (`5.12 µs` IPC), SQLite L2 cache (`>100k req/s`), JSON write overlay, and resource governor (`eco` / `balanced` / `turbo` / `auto`). | Runs on all platforms (Windows/Linux/macOS). Requires PyGhidra + OpenJDK 21 only when attached to a live `.rep`. |
| **Binary & C++ Recovery (`formats`)** | ELF / PE / Mach-O loader, MSVC RTTI & MFC `CRuntimeClass` recovery, `Serialize()` layout tracing, `CArchive` decoder, PDB MSF 7.0 / GSI hash stream and TPI CodeView leaf type records, DWARF 5 / Breakpad / `.map` export. | Pure Python; zero JVM or Ghidra dependency. |
| **Lifter & Z3 Prover (`[smt]`)** | Pure-Python ARM64 $\rightarrow$ P-code lifter (integer, exclusive memory, SIMD vector arithmetic, ARMv8.1-A atomics), x86/ARM/Thumb decoders, and Z3 equivalence prover for testing whether decompiled C matches lifted IR. | Requires `z3-solver`. **By design, returns `UNKNOWN` instead of guessing** on floating-point ops, unhandled instructions, or unbounded loops. |
| **GPU / SIMD ARM64 Scanner (`[gpu]`)** | Scans ARM64 binaries for `ADRP + ADD/LDR` pairs and function prologues (`20 MB` / `5.2M` insns in `41.20 ms` = `127.25 M insn/s` on RTX A5500). | Uses WGPU (DirectX 12 / Vulkan / Metal) for blocks $\ge 5\text{ MB}$. **Automatically falls back to NumPy CPU SIMD** (`143.95 M insn/s` on 4 MB blocks) when $< 5\text{ MB}$ or when no GPU is present. |
| **Cross-Version Matcher (`diff`)** | Matches functions across binary builds using CFG feature vectors, detects shifted struct field offsets, and rewrites field accesses. | Runs on CPU (NumPy accelerated). |
| **Storage Codec (`[storage]`)** | Compresses Ghidra 16 KB `BufferFile` pages using LZ4 (`442.9 MB/s`, `79.32%` savings) or Zstd Level 3 (`206.5 MB/s`, `86.47%` savings). | Requires `lz4` and `zstandard` packages; includes standalone Java `BufferFile` codec. |
| **Mobile & LLM Naming (`[frida]`)** | APK $\leftrightarrow$ JNI cross-referencer, allow-listed Android emulator memory reader, and guarded LLM symbol/struct naming pipeline. | Commits symbols/structs **only** after automated validation of vtable slots, field offsets, and allocation sizes. |

Each package has its own README under [`superghidra/`](superghidra/).

## Results so far

All benchmarks are measured on physical hardware (Intel Core i9-12950HX, 64 GB DDR5, NVIDIA RTX A5500 Laptop GPU) and across the multi-platform CI matrix. Full empirical data and logs are in [`docs/benchmarks/`](docs/benchmarks/).

### Hardware & Throughput Matrix

| Workload / Benchmark | Input Size / Target | Engine / Backend | Measured Time | Measured Throughput / Result | Status |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **ARM64 ADRP + ADD/LDR Sweep** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **7.28 ms** | **143.95 M insn/s** | 754 pairs detected (314 synthetic + 440 random matches) |
| **ARM64 Function Seeder** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **8.31 ms** | **126.19 M insn/s** | 16,382 candidate hits (277 deduplicated seeds) |
| **Large-scale GPU ADRP Sweep** | 20.0 MB ARM64 block (5,242,880 insns) | WGPU DirectX 12 | **41.20 ms** | **127.25 M insn/s** | Bit-exact match with CPU |
| **Buffer File Compression (LZ4)** | 1,000 synthetic 16 KB pages (16.0 MB) | LZ4 `block` | **36.12 ms** | **442.9 MB/s** (4.84x ratio) | 79.32% disk savings |
| **Buffer File Compression (Zstd)** | 1,000 synthetic 16 KB pages (16.0 MB) | Zstd Level 3 | **77.48 ms** | **206.5 MB/s** (7.39x ratio) | 86.47% disk savings |
| **Decompilation Query Cache** | Live Ghidra Daemon RPC | SQLite L2 Cache | **< 0.01 ms** | **> 100,000 req/s** | In-memory overlay match |
| **SHM Channel IPC Roundtrip** | 64 KB memory-mapped ring buffer | Windows SHM IPC | **5.12 µs** | **195,300 msg/s** | Zero-copy shared memory |

### Out-of-Distribution Systems Matrix (Uncontaminated Decompilation Verification)

Addresses the dataset contamination problem in neural decompiler benchmarks (such as HumanEval-Decompile) where models recall memorized pretraining code. Evaluated under MSVC 14.44 `cl.exe` / MinGW GCC 16.2.0 via differential co-execution:

| Workload ID | Systems Role & Target Kernel | Raw Ghidra Semantics | LLM Raw Syntax ($R_{syn}$) | LLM Semantic Pass ($R_{sem}$) | Gate 2 Hallucination Catch | SuperGhidra Verified Pass |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `SHA256_ROUND` | Crypto compression quarter-step (Ch, Maj, 32-bit rotations) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `CHACHA20_QR` | ChaCha20 quarter-round permutation (rotation invariants) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `RFC1071_CHECKSUM` | 16-bit 1's complement folded Internet checksum | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `LEB128_DECODE` | DWARF/WASM unsigned LEB128 variable-length integer parsing | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SPSC_RING_BUFFER` | Lock-free SPSC ring buffer (64-bit pointer alignment padding) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SLAB_ALLOC_HEADER` | Slab chunk header bitflag extraction (`size & ~0x7`) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |

- **Finding:** Raw LLM predictions achieved a 100% compilation rate but a 0.0% semantic pass rate due to subtle binary logic hallucinations. SuperGhidra's D-LiFT / CoExec gate rejected 100% of hallucinated candidates prior to commit.

### Reference Puzzle Baseline: HumanEval-Decompile (1,296 Evaluated Functions)

<!-- humaneval:begin -->
| Metric | IDA raw | IDA + filter | Ghidra raw | Ghidra + filter |
| :--- | :---: | :---: | :---: | :---: |
| **Pass Rate** | 243/1300 (18.69%) | 247/1300 (19.0%) | 107/1300 (8.23%) | 294/1300 (22.62%) |
| **Filter Gains** | — | +4 | — | +187 |
| **Filter Regressions** | — | -0 | — | -0 |

- **Dataset:** `LLM4Binary/decompile-eval@b9271fae3c556e46948559f4176ffa6f8b4f9491` (1300 evaluable functions from binaries compiled at `O0`–`O3`).
- **Compiler & Host:** Evaluated on `Windows AMD64` by recompiling recovered C/C++ with `gcc.EXE (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 16.2.0` under `gcc -O0 -lm`.
- **Host ABI Note:** Single-host evaluation. Linux ELF binaries recompiled on Windows (LLP64) experience 32-bit `long` truncation on raw Ghidra emissions (8.23%). On Linux (LP64), raw Ghidra achieves 21.46% (279/1300), exceeding raw IDA.
<!-- humaneval:end -->

### Dual-OS Test Matrix (GitHub Actions CI)

Full 6-job matrix evaluated with `pytest tests -v -rs -rx --strict-markers` (all integration tests run; skipped reasons reported):

| Operating System | Python 3.10 | Python 3.11 | Python 3.12 | Pytest Test Count | Pass Rate (passed / active) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Ubuntu Linux** (`ubuntu-latest`) | 42s | 30s | 27s | 736 collected (715 passed, 21 skipped) | 100% |
| **Windows Server** (`windows-latest`) | 1m 24s | 1m 12s | 1m 14s | 736 collected (715 passed, 21 skipped) | 100% |

Detailed logs and measurement methodology are documented in [`docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md`](docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md).

## Installation

**From PyPI:**

```bash
pip install superghidra
```

Optional acceleration and integration extras:

```bash
pip install "superghidra[all]"       # all optional backends
pip install "superghidra[smt]"       # Z3 P-code equivalence checker
pip install "superghidra[gpu]"       # WGPU compute shaders (ADRP/prologue sweeps)
pip install "superghidra[storage]"   # LZ4 & Zstandard 16 KB page compression
pip install "superghidra[ghidra]"    # PyGhidra bridge & JVM headless bindings
pip install "superghidra[frida]"     # Live emulator runtime inspection
```

**From source (development):**

```bash
git clone https://github.com/yuatemycat/SuperGhidra
cd SuperGhidra
pip install -e ".[all]"
python -m pytest -q
```

**Unified CLI:**

SuperGhidra ships with an integrated standalone command-line executable `superghidra`:

```bash
# Display version and hardware acceleration telemetry
superghidra version

# Staged P-code decompiler (handles register-to-register mov/add/xor and ret on x86-64; any other instruction exits non-zero)
superghidra decompile target.dll --va 0x140001000 --arch x86_64 -o decompiled.c

# Import IDA Pro .til type library and dump schema catalog
superghidra til-import mssdk64.til -o catalog.json

# Match binary bytes against IDA FLIRT signature database
superghidra flirt-match vc32rtf.sig target.exe --rva 0x1000

# Recover MSVC / MFC C++ class hierarchies, RTTI structures, and virtual call tables
superghidra rtti-recover app.dll -o classes.json

# Filter raw decompiler output into clean, compilable C
superghidra filter raw_decompile.c -o clean.c

# Sync JSON write overlays and delta logs into an atomic Ghidra GUI Python script
superghidra overlay-sync --overlay ghidra_overlay.json --out sync_script.py
```

**Inspect a Windows binary (no Ghidra needed):**

```bash
python -m superghidra.formats.binary_loader app.dll          # sections, imports, exports
python -m superghidra.formats.msvc_class_recovery app.dll    # RTTI + MFC classes
python -m superghidra.formats.serialize_trace app.dll CMyDoc # Serialize() field layout
```

**From Python:**

```python
from superghidra.formats.binary_loader import load_binary
from superghidra.formats.msvc_class_recovery import recover_classes
import superghidra as sg

img = load_binary("app.dll")
print(img.format, img.arch, len(img.sections))

report = recover_classes("app.dll")
print(len(report.mfc_classes), "MFC classes")

# Lift one ARM64 instruction and check it against itself with Z3
ops = sg.ARM64PcodeLifter().lift_instruction(0x1000, 0x91008041)  # add x1, x2, #0x20
print(sg.SMTPcodeVerifier().verify_equivalence(ops, ops).equivalent)
```

**Configuration** is read from environment variables, and nothing is tied to a particular machine:

| Variable | Used for |
| :--- | :--- |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | Ghidra and JDK locations (daemon, headless runs, Java codec build) |
| `SUPERGHIDRA_PROJECTS` | Default projects for the daemon: `dir,name[,program]` entries joined by `;` |
| `SUPERGHIDRA_MSVC_ROOT` | Portable MSVC folder, used when gcc/clang aren't on `PATH` |
| `SUPERGHIDRA_TEST_ARM64_ELF`, `SUPERGHIDRA_TEST_SWDM`, `SUPERGHIDRA_TEST_SW_ROOT` | Optional real binaries / a SOLIDWORKS install for the integration tests. Those tests skip when unset. |

## Troubleshooting & Common Gotchas

* **`superghidra decompile` fails or outputs empty blocks on my function:**
  You ran the standalone experimental zero-JVM integer lifter. Switch to `python ghidra_oracle.py decompile <addr>`.
* **`LockException: Project is locked by another process`:**
  Your `.rep` project is currently open in the Ghidra GUI. The daemon reads from the project without acquiring exclusive locks; if Ghidra holds an exclusive lock or you encounter lock contention, ensure the daemon uses a read-only session or private session fork, and sync changes back via `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py`.
* **My renamed functions in the daemon don't show up in the Ghidra GUI:**
  Daemon writes go to the JSON overlay (`ghidra_overlay.json`) to prevent `.rep` corruption. Run `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py` and execute that script inside Ghidra's Script Manager, or close the GUI and run `merge_fork`.
* **Z3 Equivalence Checker returns `UNKNOWN`:**
  This is expected behavior, not a crash. The prover returns `UNKNOWN` whenever a block contains floating-point instructions, unmodeled system instructions, or long loops so an agent never commits a false-positive equivalence rewrite.
* **WGPU scanner says `Using CPU SIMD path` even with `[gpu]` installed:**
  For ARM64 `.text` blocks under 5 MB, PCIe transfer overhead exceeds shader execution time, so SuperGhidra automatically routes blocks `< 5 MB` to the NumPy SIMD path (`143.95 M insn/s`).
* **Proposed struct or symbol from the LLM naming pipeline was rejected:**
  The naming pipeline enforces structural invariants before writing to the overlay. Check the daemon log for `VtableSlotMismatch`, `FieldOffsetOutOfBounds`, or `AllocationSizeConflict`.

## Known limitations

- The Java codec doesn't compress Ghidra projects transparently. Ghidra hardcodes `LocalManagedBufferFile` with no storage hook, so the SuperGhidra codec operates on external `.sgdb` files or requires patching Ghidra's core jar.
- PDB export implements CodeView 7.0 MSF structures with a Global Symbol Index (GSI) 4096-bucket hash table; MSVC and LLVM toolchains can read symbols, while complex type streams remain under active expansion.
- The SMT checker is sound but incomplete. Floats, calls, unhandled ops and long loops return `UNKNOWN` by design to prevent false equivalence.
- The ARM64 lifter covers core integer, exclusive memory, SIMD vector math/bitwise, and ARMv8.1-A atomics. Advanced cryptographic and complex floating-point vector ops remain unimplemented.
- The LLM naming stage needs a real endpoint. Without one, it falls back to neutral names such as `sub_<addr>`, labelled `heuristic-fallback`.
- Detailed audit analysis, cross-backend telemetry, and resolution plans are documented in [`docs/specs/AUDIT_RECONCILIATION_REPORT.md`](docs/specs/AUDIT_RECONCILIATION_REPORT.md).

More detail is in [PLAN.md](PLAN.md).

## Repository layout

```
superghidra/   the package, split into the seven areas above
tests/         pytest suites, one folder per area
docs/          benchmark reports and design notes
ghidra_extension_skeleton/   Java BufferFile codec
*.py           thin shims so `import binary_loader` etc. keep working for older callers
```

If you're an AI agent, start with [AGENTS.md](AGENTS.md).

## Donate

If you find SuperGhidra useful, crypto donations (fast & permissionless) are welcome:

**USDT (BEP20 / BNB Smart Chain):**

```
0xd08d47bde441888166b801616754c667672cd502
```

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test workflow and the safety rules: read-only projects, verified symbol commits and the emulator allow-list. Report security issues as described in [SECURITY.md](SECURITY.md).

## License

SuperGhidra is licensed under the [GNU AGPL-3.0-or-later](LICENSE). If you modify it and let other people use it over a network, for example as a hosted MCP server, you have to offer them your modified source.

If the AGPL doesn't fit your use, a commercial license is available. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

Releases up to and including 0.2.0, and commits before the license change, were published under Apache-2.0. Those versions stay under Apache-2.0 and the text is kept in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

© 2026 yuatemycat and contributors.
