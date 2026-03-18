CTF Write-up: Joe Pedri — Android Mobile Challenge
Event: ST4F1T CTF
Category: Mobile / Reverse Engineering
Difficulty: Med-Hard

Challenge Description
We are given an Android APK named Joe Pedri, simulating a cybersecurity scanner interface with multiple scan outputs. The app appears to reveal a flag early on, but things are not what they seem.
Step 1 — Decompile the APK
Open the APK in JADX and navigate to:
com.st4f1t.joe_pedri.MainActivity
Step 2 — Identify the Fake Flags

runScanB() shows ST4F1T{H00ki_4b4n4} — the code itself says "Maybe not" → decoy
f4() builds a shuffled ST4F1T{n0pe_br0} → decoy
Functions f2() through f7() are obfuscation red herrings, never part of the real flow

Step 3 — Find the Real Flag Logic
javapublic final native String generateFlagNative(String key);
public final native String getSecretKey();
The real flag is inside libjoe_pedri.so — static analysis is not enough, we need Frida.
Step 4 — Set Up the Environment
powershellpip install frida-tools
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
adb install joe_pedri.apk
Step 5 — Write the Hook
Create hook.js:
javascriptJava.perform(function () {
    var MainActivity = Java.use("com.st4f1t.joe_pedri.MainActivity");

    MainActivity.generateFlagNative.implementation = function (key) {
        var flag = this.generateFlagNative(key);
        console.log("[+] FLAG: " + flag);
        return flag;
    };

    Java.choose("com.st4f1t.joe_pedri.MainActivity", {
        onMatch: function (instance) {
            var key = instance.getSecretKey();
            console.log("[*] Key: " + key);
            instance.f1(key);
        },
        onComplete: function () {}
    });
});
Step 6 — Run Frida
powershellfrida -U -f com.st4f1t.joe_pedri -l hook.js
```

## Step 7 — Get the Flag
Frida intercepts the native call and prints:
```
[*] Key: <secret_key>
[+] FLAG: ST4F1T{<real_flag>}

Flag: ST4F1T{<real_flag>}
