# CTF Rev — Dig Deeper Challenge Write-up

**Event:** ST4F1T &nbsp;&nbsp; **Category:** Reverse Engineering

---

## Challenge Description

A file called `challenge.pdf` was given. Its only visible content is the phrase **"dig deeper"**. Our job is to figure out what is hidden inside and find the flag.

---

## Step 1 — Check the File Type

The first thing I did is run `strings` on the file to see what's inside. Just because something is named `.pdf` doesn't mean it only contains a PDF.

```bash
strings challenge.pdf
```

The output revealed two different things living inside the same file:

- A valid **PDF 1.7** structure with LibreOffice metadata
- **ELF binary** artifacts — `/lib64/ld-linux-x86-64.so.2`, `libc.so.6`, C runtime functions (`puts`, `sleep`, `malloc`), GCC compiler info, and ELF section names (`.text`, `.data`, `.bss`)
- A suspicious string: `[*] Initialising... please wait.`

This is a **polyglot file** — a single file that is simultaneously a valid PDF and a hidden ELF executable.

---

## Step 2 — Locating the Hidden ELF Binary

PDF files always end with the marker `%%EOF`. Anything after it is ignored by PDF readers — but can still be executed by Linux. I searched for this boundary:

```bash
grep -a -b '%%EOF' challenge.pdf
```

```
13041:%%EOF
```

Then I inspected the raw bytes right after `%%EOF`:

```python
data = open('challenge.pdf', 'rb').read()
idx  = data.find(b'%%EOF')
rest = data[idx + 5:]
print('First bytes:', rest[:16].hex())
```

Output:
```
0a 7f 45 4c 46 ...
```

- `0x0a` = newline
- `7f 45 4c 46` = ELF magic bytes

The ELF starts at offset **13047**.

---

## Step 3 — Extracting the ELF Binary

```bash
dd if=challenge.pdf of=challenge.elf bs=1 skip=13047
file challenge.elf
```

```
challenge.elf: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

We have our binary.

---

## Step 4 — Running the Binary

```bash
chmod +x challenge.elf
./challenge.elf
```

```
[*] Initialising... please wait.
```

It just hangs. I used `ltrace` to trace library calls and see what it's actually doing:

```bash
ltrace ./challenge.elf
```

```
puts("[*] Initialising... please wait.")
fflush(0x...)
sleep(43200)
```

`43200 seconds = 12 hours`. The binary deliberately sleeps for 12 hours as an anti-analysis trick to make dynamic analysis painful.

---

## Step 5 — Bypassing the Sleep with GDB

I used GDB to intercept the `sleep()` call and return from it immediately without waiting:

```bash
gdb ./challenge.elf
(gdb) break sleep
(gdb) run
```

```
[*] Initialising... please wait.
Breakpoint 1 hit — sleep() intercepted
```

```
(gdb) return (int)0
(gdb) continue
```

```
tinyurl.com/4azx8mse
```

The binary outputs a URL. Let's follow it.

---

## Step 6 — Decoding the URL Payload (Gzip + Base64)

The URL returned a PowerShell script containing a large encoded blob:

```powershell
$b = "H4sIAB1ArGkC/01STW/iMBC9..."
```

I decoded it:

```bash
echo "<base64_string>" | base64 -d | gunzip
```

The output was another PowerShell script with a **reversed** base64 string:

```powershell
$data = "=ogI90zZDB3a..."
$out  = -join ($data[-1..-($data.Length)])
```

---

## Step 7 — Reversing and Decoding (Double Base64)

```python
import base64

data         = '=ogI90zZDB3a...'
reversed_b64 = data[::-1]
decoded      = base64.b64decode(reversed_b64).decode()
print(decoded)
```

This revealed the final layer — a PowerShell XOR decryption routine:

```powershell
$key    = 0x5A
$hex    = "7d090e6e1c6b0e21093932286a3e33343d3f2805296a362c3f3e05373f277d"
$bytes  = [byte[]]($hex -split '(?<=\G.{2})' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
$result = [string]::join("", ($bytes | ForEach-Object { [char]($_ -bxor $key) }))
```

---

## Step 8 — XOR Decryption

I replicated the XOR logic in Python:

```python
key      = 0x5A
hex_data = "7d090e6e1c6b0e21093932286a3e33343d3f2805296a362c3f3e05373f277d"
result   = ''.join(chr(b ^ key) for b in bytes.fromhex(hex_data))
print(result)
```

---

## Flag

```
ST4F1T{Schr0dinger_s0lved_me}
```

> The flag references **Schrödinger's cat** — fitting for a file that exists as both a PDF and an ELF binary at the same time, just like the cat being simultaneously alive and dead.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `strings` | Initial content discovery |
| `grep` / `python3` | Locate ELF offset inside the PDF |
| `dd` | Extract the ELF binary by byte offset |
| `file` | Confirm extracted file type |
| `ltrace` | Trace library calls — revealed `sleep(43200)` |
| `GDB` | Bypass the sleep at runtime |
| `python3` | Base64 decoding, gzip decompression, XOR decryption |
