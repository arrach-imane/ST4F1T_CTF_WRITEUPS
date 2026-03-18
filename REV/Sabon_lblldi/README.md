Reverse Engineering — sabon_lblldi Write-up

Event: ST4F1T
Category: Reverse Engineering

📌 Challenge Description

We are given a binary named sabon_lblldi.exe.
Running it prompts for a password, and our objective is to recover the correct input that reveals the flag.

At first glance, nothing obvious is exposed, so we proceed with standard reverse engineering methodology.

🔍 Step 1 — Initial Binary Inspection

Before opening any disassembler, I checked the binary format:

file sabon_lblldi.exe

The output shows:

PE32 executable (console) Intel 80386, for MS Windows, UPX compressed

This immediately tells us two things:

It’s a 32-bit Windows executable

It is packed using UPX

Packed binaries hide their real code, so analyzing it in this state would be misleading.

👉 The correct next step is to unpack it.

📦 Step 2 — Unpacking the Binary

I used UPX to restore the original executable:

upx -d sabon_lblldi.exe -o sabon_lblldi_unpacked.exe

Now the binary is ready for proper static analysis.

🔬 Step 3 — Static Analysis with Ghidra

After loading the unpacked binary into Ghidra and analyzing it, I located the main logic responsible for user interaction:

FUN_00401a59
What this function does:

Displays the prompt "password:"

Reads user input using fgets

Passes the input to a validation function:

FUN_004019f7(input)

So the core of the challenge is inside this validation routine.

🔐 Step 4 — Understanding the Validation Logic

The function responsible for checking the password is:

FUN_00401965
Simplified logic:
len1 = strlen(input);
len2 = strlen(expected);

result = len1 ^ len2;

for each byte:
    result |= input[i] ^ expected[i];

return (result == 0);
Analysis:

It compares both length and content

Uses XOR to accumulate differences

Avoids early exit (similar to constant-time comparison)

👉 This confirms that the program compares the input with a hidden string stored somewhere else.

So the real goal becomes:

🔎 Find and reconstruct the hidden expected string

🧩 Step 5 — Locating the Hidden Password

Tracing back where the expected string comes from:

FUN_004019f7 → FUN_00401937 → FUN_004017fb → FUN_0040178e
Step 5.1 — Encoded Data Initialization

Inside:

FUN_004017fb

We find a hardcoded byte array:

0x61, 0x66, 0x06, 0x74, 0x03, 0x66, 0x49, 0x54, ...

This is clearly not readable ASCII → encoded data.

Step 5.2 — Transformation Function

The buffer is then processed by:

FUN_0040178e(buffer, size, 0x32)

Which internally calls:

FUN_00401737(buffer, size, key)

Core operation:

buffer[i] ^= 0x32;

👉 This is a simple XOR decryption with key 0x32

🧮 Step 6 — Decoding the Password

Now that we understand the encoding, we can reconstruct the hidden string.

Python script:
data = [
0x61,0x66,0x06,0x74,0x03,0x66,0x49,0x54,0x5b,0x40,
0x41,0x46,0x6d,0x41,0x46,0x40,0x5b,0x42,0x42,0x57,
0x56,0x6d,0x50,0x5b,0x5c,0x06,0x40,0x4b,0x4f
]

print(''.join(chr(x ^ 0x32) for x in data))
Output:
ST4F1T{first_stripped_bin4ry}
🧠 Step 7 — Final Behavior

When the correct password is provided:

The comparison function returns success

The program calls a success routine

The flag is printed

Other functions present in the binary (recursive chains with multiple constants) act as noise/obfuscation and do not influence the validation logic.

🧰 Tools Used
Tool	Purpose
file	Identify binary format and packing
upx	Unpack the executable
Ghidra	Static reverse engineering
Python	Decode XOR-obfuscated data
