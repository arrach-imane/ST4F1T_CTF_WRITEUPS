# 🧠 sabon_lblldi — Reverse Engineering Write-up

> **Event:** ST4F1T &nbsp;|&nbsp; **Category:** Reverse Engineering &nbsp;|&nbsp; **Flag:** `ST4F1T{first_stripped_bin4ry}`

---

## 📌 Challenge Overview

We're handed a binary called `sabon_lblldi.exe`. It runs, prompts for a password, and our job is to figure out what that password is — and grab the flag.

No source code. No hints. Just the binary.

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify binary format and detect packing |
| `upx` | Unpack the UPX-compressed executable |
| Ghidra | Static reverse engineering and control flow analysis |
| Python | XOR decode the obfuscated password |

---

## 🔍 Step 1 — Initial Inspection

Before touching a disassembler, always start with `file`:

```bash
file sabon_lblldi.exe
```

Output:

```
PE32 executable (console) Intel 80386, for MS Windows, UPX compressed
```

Two immediate observations:

- 32-bit Windows PE binary
- **UPX packed** — the real code is hidden

Analyzing a packed binary in this state is misleading. The disassembler sees the unpacker stub, not the actual logic. We unpack first.

---

## 📦 Step 2 — Unpacking with UPX

```bash
upx -d sabon_lblldi.exe -o sabon_lblldi_unpacked.exe
```

Now the binary is restored to its original form and ready for proper static analysis.

---

## 🔬 Step 3 — Static Analysis in Ghidra

Loading the unpacked binary into Ghidra and running auto-analysis, we locate the main entry point:

```
FUN_00401a59
```

This function:
- Prints the prompt `"password:"`
- Reads user input via `fgets`
- Passes it to a validation routine: `FUN_004019f7(input)`

The challenge lives inside that validation routine.

---

## 🔐 Step 4 — The Validation Logic

The comparison happens in `FUN_00401965`. Simplified:

```c
len1 = strlen(input);
len2 = strlen(expected);

result = len1 ^ len2;

for each byte i:
    result |= input[i] ^ expected[i];

return (result == 0);
```

Key observations:

- Compares both **length and content**
- Uses XOR to accumulate all differences into a single value
- **No early exit** — intentionally mimics constant-time comparison to resist timing side-channels (or just to look scarier)

The input is compared against a hidden string. Our goal: find and reconstruct that string.

---

## 🧩 Step 5 — Tracing the Hidden Password

Following the call chain from the validation function:

```
FUN_004019f7  →  FUN_00401937  →  FUN_004017fb  →  FUN_0040178e
```

### 5.1 — The Encoded Byte Array

Inside `FUN_004017fb`, a hardcoded byte array is initialized:

```c
0x61, 0x66, 0x06, 0x74, 0x03, 0x66, 0x49, 0x54, ...
```

Not readable ASCII — this is encoded data.

### 5.2 — The Decoding Routine

The array is passed to:

```c
FUN_0040178e(buffer, size, 0x32)
```

Which calls `FUN_00401737(buffer, size, key)`. Core operation:

```c
buffer[i] ^= 0x32;
```

Simple XOR cipher with key `0x32`.

---

## 🧮 Step 6 — Decoding the Password

Armed with the byte array and the key, decoding is trivial:

```python
data = [
    0x61, 0x66, 0x06, 0x74, 0x03, 0x66, 0x49, 0x54, 0x5b, 0x40,
    0x41, 0x46, 0x6d, 0x41, 0x46, 0x40, 0x5b, 0x42, 0x42, 0x57,
    0x56, 0x6d, 0x50, 0x5b, 0x5c, 0x06, 0x40, 0x4b, 0x4f
]

print(''.join(chr(x ^ 0x32) for x in data))
```

Output:

```
ST4F1T{first_stripped_bin4ry}
```

---

## 🏁 Step 7 — Full Execution

Feeding this as the password:

1. `FUN_00401965` receives the input
2. XOR comparison across all bytes returns `0`
3. Validation returns success
4. The program calls its success routine and prints the flag

> The binary contains additional recursive functions with various constants. These are noise — obfuscation to pad the call graph. They play no role in the validation path.


## 🚩 Flag

```
ST4F1T{first_stripped_bin4ry}
```
