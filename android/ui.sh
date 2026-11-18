#!/bin/bash
# Dev helper: print visible texts (with tap coordinates) of the app via uiautomator.
# Usage: ./ui.sh            -> list
#        ./ui.sh tap "Text" -> tap the element whose text/desc contains Text
export PATH=$PATH:$HOME/Android/Sdk/platform-tools
adb shell uiautomator dump --compressed /sdcard/rg-ui.xml >/dev/null 2>&1
adb pull /sdcard/rg-ui.xml /tmp/rg-ui.xml >/dev/null 2>&1
adb shell rm /sdcard/rg-ui.xml
python3 - "$@" <<'EOF'
import re, sys, subprocess, html
x = open("/tmp/rg-ui.xml", encoding="utf-8").read()
nodes = []
for m in re.finditer(r'<node [^>]*>', x):
    n = m.group(0)
    t = html.unescape((re.search(r' text="([^"]*)"', n) or [None, ""])[1])
    d = html.unescape((re.search(r' content-desc="([^"]*)"', n) or [None, ""])[1])
    b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', n)
    if (t or d) and b:
        x1, y1, x2, y2 = map(int, b.groups())
        nodes.append(((x1 + x2) // 2, (y1 + y2) // 2, t or d))
if len(sys.argv) > 2 and sys.argv[1] == "tap":
    want = sys.argv[2]
    for cx, cy, label in nodes:
        if want in label:
            subprocess.run(["adb", "shell", "input", "tap", str(cx), str(cy)])
            print(f"tapped '{label}' at {cx},{cy}")
            break
    else:
        print("not found:", want)
else:
    for cx, cy, label in nodes:
        print(f"{cx:5},{cy:5}  {label}")
EOF
