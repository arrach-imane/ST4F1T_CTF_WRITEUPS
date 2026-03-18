# Joe Pedri — CTF Write-up

> **Event:** ST4F1T CTF  
> **Category:** Mobile / Reverse Engineering  
> **Difficulty:** Med-Hard 
> **Flag:** `ST4F1T{REDACTED}`

---

## Table of Contents

- [Challenge Description](#challenge-description)
- [Tools Used](#tools-used)
- [Step 1 — Static Analysis with JADX](#step-1--static-analysis-with-jadx)
- [Step 2 — Identifying the Fake Flags](#step-2--identifying-the-fake-flags)
- [Step 3 — Finding the Real Flag Mechanism](#step-3--finding-the-real-flag-mechanism)
- [Step 4 — Setting Up the Environment](#step-4--setting-up-the-environment)
- [Step 5 — Writing the Frida Hook](#step-5--writing-the-frida-hook)
- [Step 6 — Running Frida and Extracting the Flag](#step-6--running-frida-and-extracting-the-flag)
- [Summary](#summary)
- [Key Lessons](#key-lessons)

---

## Challenge Description

We are given an Android APK named **Joe Pedri** that simulates a cybersecurity scanner interface. On the surface, the app displays port scan results, vulnerability outputs, and hash values — and even appears to reveal a flag early on.

The challenge is to figure out what is real and what is a decoy, and to extract the actual flag hidden inside a native library.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [JADX](https://github.com/skylot/jadx) | Decompile the APK and read the Java source |
| [Frida](https://frida.re) | Dynamic instrumentation / runtime hooking |
| Android Studio | Run a rooted AVD emulator |
| ADB | Communicate with the emulator |

---

## Step 1 — Static Analysis with JADX

Open the APK in JADX and navigate to the main class:

```
com.st4f1t.joe_pedri.MainActivity
```

Inside, we find a button that cycles through three scan functions on each click:

```java
switch (this$0.clickCount % 3) {
    case 0: this$0.runScanA(); break;  // fake port scan
    case 1: this$0.runScanB(); break;  // suspicious flag output
    case 2: this$0.runScanC(); break;  // fake hash results
}
```

We also notice several obfuscated helper functions (`f2` through `f7`) and two **native method** declarations — which is the most important discovery.

---

## Step 2 — Identifying the Fake Flags

The app contains multiple decoys designed to mislead analysts.

### Fake Flag #1 — `runScanB()`

```java
textView.setText("Found: ST4F1T{H00ki_4b4n4}\n[!] Wait... is this the flag? Maybe not.");
```

The app literally tells you it's fake. Move on.

### Fake Flag #2 — `f4()`

```java
private final String f4() {
    List parts = CollectionsKt.listOf(new String[]{"5T", "4F", "1T", "{", "n0p", "e_", "br0", "}"});
    return CollectionsKt.joinToString(CollectionsKt.shuffled(parts), ...);
}
```

This builds a **randomly shuffled** version of `ST4F1T{n0pe_br0}`. It is never called in any real flow — pure red herring.

### Obfuscation Functions

The functions `f2()` through `f7()` exist only to waste your time:

- `f2()` — reverses a string and shifts each character by +1
- `f3()` — XOR hash check, never meaningfully called
- `f5()` — XORs each character with its index × 19
- `f6()` — pointless bitwise arithmetic
- `f7()` — swaps uppercase and lowercase letters

None of these are part of the real flag flow.

---

## Step 3 — Finding the Real Flag Mechanism

The real logic is here:

```java
public final native String generateFlagNative(String key);
public final native String getSecretKey();

public final void f1(String key) {
    String result = generateFlagNative(key);
    Log.d("JOEPEDRI", "[+] FLAG: " + result);
    tvOutput.setText(">> Flag unlocked!\n[+] FLAG: " + result);
}
```

And the native library is loaded with:

```java
System.loadLibrary("joe_pedri");
```

The real flag is generated inside **`libjoe_pedri.so`**. Static analysis cannot go further here — we need to hook these functions at runtime using **Frida**.

---

## Step 4 — Setting Up the Environment

### 1. Install Frida on your machine

```bash
pip install frida-tools
frida --version
```

### 2. Set up the emulator

In Android Studio, create an AVD using a **Google APIs** image (not Google Play) — this gives you root access.

### 3. Push frida-server to the emulator

Download the correct `frida-server` binary for your emulator architecture from the [Frida releases page](https://github.com/frida/frida/releases), then:

```bash
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
```

### 4. Start frida-server (keep this running)

```bash
adb shell "/data/local/tmp/frida-server &"
```

### 5. Install the APK

```bash
adb install joe_pedri.apk
```

---

## Step 5 — Writing the Frida Hook

Create a file called `hook.js`:

```javascript
Java.perform(function () {

    var MainActivity = Java.use("com.st4f1t.joe_pedri.MainActivity");

    // Intercept the secret key
    MainActivity.getSecretKey.implementation = function () {
        var key = this.getSecretKey();
        console.log("[*] getSecretKey() returned: " + key);
        return key;
    };

    // Intercept the flag generation
    MainActivity.generateFlagNative.implementation = function (key) {
        console.log("[*] generateFlagNative called with key: " + key);
        var flag = this.generateFlagNative(key);
        console.log("[+] FLAG: " + flag);
        return flag;
    };

    // Find the live MainActivity instance and trigger the flag directly
    Java.choose("com.st4f1t.joe_pedri.MainActivity", {
        onMatch: function (instance) {
            console.log("[*] Found MainActivity instance");
            var key = instance.getSecretKey();
            instance.f1(key);
        },
        onComplete: function () {}
    });

});
```

---

## Step 6 — Running Frida and Extracting the Flag

```bash
frida -U -f com.st4f1t.joe_pedri -l hook.js
```

Frida spawns the app, injects the hook, and the console prints:

```
[*] Found MainActivity instance
[*] getSecretKey() returned: <secret_key>
[*] generateFlagNative called with key: <secret_key>
[+] FLAG: ST4F1T{<real_flag>}
```

---

## Summary

| Element | What it was |
|---------|------------|
| `ST4F1T{H00ki_4b4n4}` in `runScanB()` | Fake flag — the code itself says so |
| `ST4F1T{n0pe_br0}` in `f4()` | Fake flag — shuffled, never called |
| `f2()` through `f7()` | Obfuscation red herrings |
| `getSecretKey()` | Native method returning the real key |
| `generateFlagNative(key)` | Native method generating the real flag |
| Frida hook on `f1()` | Bypasses the native layer and captures the output |

---

## Key Lessons

- **Read the code, not just the output** — the fake flag literally labeled itself as fake
- **Native methods are a wall for static analysis** — when you see `native`, think Frida
- **Frida lets the app decrypt itself** — no need to reverse the `.so`, just hook the result
- **Red herrings are intentional** — recognizing them fast is half the challenge
