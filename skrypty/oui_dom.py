#!/usr/bin/env python3
"""
Tworzy oui_dom.h - wbudowana w program Radar Sieci baza producentow
(adres MAC -> marka) dla sprzetu spotykanego w domach. Dzieki temu
rozpoznawanie producenta dziala bez karty SD i bez internetu.

Uzycie:
    python oui_dom.py [oui.txt albo oui.csv] [oui_dom.h]
Bez argumentow pobiera aktualna baze z IEEE (https://standards-oui.ieee.org/oui/oui.csv).
Gotowy plik oui_dom.h skopiuj do folderu szkicu radar_sieci.

Format: posortowana tablica uint32: (3 bajty prefiksu MAC << 8) | numer marki.
Program szuka binarnie - ok. 14 porownan.
"""
import csv
import datetime
import io
import re
import sys
import urllib.request

# (fragment nazwy firmy w bazie IEEE, male litery) -> krotka nazwa marki.
# Kolejnosc ma znaczenie: pierwsze dopasowanie wygrywa.
BRANDS = [
    ("apple", "Apple"), ("samsung", "Samsung"), ("xiaomi", "Xiaomi"), ("honor device", "Honor"),
    ("huawei", "Huawei"), ("tp-link", "TP-Link"), ("mercury", "Mercusys"), ("d-link", "D-Link"),
    ("netgear", "Netgear"), ("asustek", "ASUS"), ("zyxel", "Zyxel"), ("routerboard", "MikroTik"),
    ("mikrotik", "MikroTik"), ("ubiquiti", "Ubiquiti"), ("cisco-linksys", "Linksys"), ("linksys", "Linksys"),
    ("belkin", "Belkin"), ("cisco", "Cisco"), ("avm audiovisuelles", "AVM FRITZ!"), ("sagemcom", "Sagemcom"),
    ("technicolor", "Technicolor"), ("arris", "ARRIS"), ("zte corporation", "ZTE"), ("arcadyan", "Arcadyan"),
    ("askey", "Askey"), ("sercomm", "Sercomm"), ("compal broadband", "Compal"), ("tenda", "Tenda"),
    ("netis", "netis"), ("zioncom", "TOTOLINK"), ("nokia", "Nokia"), ("espressif", "Espressif (IoT)"),
    ("tuya", "Tuya (smart home)"), ("hikvision", "Hikvision"), ("ezviz", "EZVIZ"), ("dahua", "Dahua"),
    ("reolink", "Reolink"), ("amazon", "Amazon"), ("google", "Google"), ("nest labs", "Google Nest"),
    ("sonos", "Sonos"), ("lg electronics", "LG"), ("lg innotek", "LG"), ("sony interactive", "PlayStation"),
    ("sony", "Sony"), ("panasonic", "Panasonic"), ("signify", "Philips Hue"), ("philips lighting", "Philips Hue"),
    ("tp vision", "Philips TV"), ("philips", "Philips"), ("roku", "Roku"), ("nintendo", "Nintendo"),
    ("microsoft", "Microsoft"), ("dell", "Dell"), ("hewlett packard", "HP"), ("hp inc", "HP"),
    ("lcfc", "Lenovo"), ("lenovo", "Lenovo"), ("motorola mobility", "Motorola"), ("acer", "Acer"),
    ("micro-star", "MSI"), ("giga-byte", "Gigabyte"), ("asrock", "ASRock"), ("intel corporate", "Intel"),
    ("realtek", "Realtek"), ("mediatek", "MediaTek"), ("liteon", "Lite-On"), ("lite-on", "Lite-On"),
    ("azurewave", "AzureWave"), ("murata", "Murata"), ("hon hai", "Foxconn"), ("raspberry pi", "Raspberry Pi"),
    ("synology", "Synology"), ("qnap", "QNAP"), ("western digital", "Western Digital"), ("seagate", "Seagate"),
    ("canon", "Canon"), ("seiko epson", "Epson"), ("brother industries", "Brother"), ("guangdong oppo", "OPPO"),
    ("vivo mobile", "vivo"), ("oneplus", "OnePlus"), ("realme", "realme"), ("fitbit", "Fitbit"),
    ("garmin", "Garmin"), ("withings", "Withings"), ("ring llc", "Ring"), ("arlo", "Arlo"), ("wyze", "Wyze"),
    ("anker", "Anker/eufy"), ("bsh hausger", "Bosch/Siemens AGD"), ("miele", "Miele"), ("dyson", "Dyson"),
    ("roborock", "Roborock"), ("ecovacs", "Ecovacs"), ("irobot", "iRobot"), ("tado", "tado"),
    ("netatmo", "Netatmo"), ("allterco", "Shelly"), ("shelly", "Shelly"), ("itead", "Sonoff"),
    ("meross", "Meross"), ("intellirocks", "Govee"), ("yeelink", "Yeelight"), ("lifx", "LIFX"),
    ("nanoleaf", "Nanoleaf"), ("valve corporation", "Valve"), ("tesla", "Tesla"), ("vestel", "Vestel"),
    ("tcl", "TCL"), ("hisense", "Hisense"), ("sharp", "Sharp"), ("toshiba", "Toshiba"),
    ("arcelik", "Beko/Grundig"), ("skyworth", "Skyworth"), ("texas instruments", "Texas Instr."),
    ("silicon laboratories", "Silicon Labs"), ("nordic semiconductor", "Nordic"), ("bose", "Bose"),
    ("jbl", "JBL"), ("harman", "Harman/JBL"), ("logitech", "Logitech"), ("xbox", "Xbox"),
    ("ezviz", "EZVIZ"), ("imou", "Imou"), ("foscam", "Foscam"), ("axis communications", "Axis"),
]
IEEE_CSV = "https://standards-oui.ieee.org/oui/oui.csv"


def load(src):
    """Zwraca liste (prefiks_hex, nazwa_firmy) z oui.csv albo oui.txt."""
    if src is None:
        req = urllib.request.Request(IEEE_CSV, headers={"User-Agent": "Mozilla/5.0 Radar-Sieci"})
        text = urllib.request.urlopen(req, timeout=120).read().decode("utf-8", "replace")
        src_name = "oui.csv"
    else:
        text = open(src, encoding="utf-8", errors="replace").read()
        src_name = src
    out = []
    if src_name.endswith(".csv"):
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
                out.append((row[1].strip().upper(), row[2]))
    else:
        for m in re.finditer(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$", text, re.M):
            out.append((m.group(1), m.group(2).strip()))
    return out


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else None
    dst = sys.argv[2] if len(sys.argv) > 2 else "oui_dom.h"
    rows = load(src)
    labels = []
    entries = {}
    for prefix, org in rows:
        low = org.lower()
        for key, label in BRANDS:
            if re.search(r"(?<![a-z0-9])" + re.escape(key) + r"(?![a-z0-9])", low):   # cale slowo
                if label not in labels:
                    labels.append(label)
                entries[int(prefix, 16)] = labels.index(label)
                break
    assert len(labels) < 256
    keys = sorted(entries)
    today = datetime.date.today().isoformat()
    with open(dst, "w", encoding="ascii", newline="\n") as f:
        f.write(f"// Wygenerowano skryptem oui_dom.py z bazy IEEE ({today}).\n")
        f.write(f"// {len(keys)} prefiksow MAC, {len(labels)} marek sprzetu domowego.\n#pragma once\n\n")
        f.write("const char* const OUI_BRANDS[] = {\n")
        for i in range(0, len(labels), 6):
            f.write("  " + ", ".join('"' + l + '"' for l in labels[i:i + 6]) + ",\n")
        f.write("};\n\n// (prefiks << 8) | numer marki, posortowane rosnaco\n")
        f.write(f"const uint32_t OUI_DOM[{len(keys)}] PROGMEM = {{\n")
        for i in range(0, len(keys), 8):
            f.write("  " + ", ".join(f"0x{(k << 8) | entries[k]:08X}" for k in keys[i:i + 8]) + ",\n")
        f.write("};\n")
        f.write(f"const uint16_t OUI_DOM_COUNT = {len(keys)};\n")
    print(f"Zapisano {dst}: {len(keys)} prefiksow, {len(labels)} marek, ok. {len(keys) * 4 // 1024} KB w programie")


if __name__ == "__main__":
    main()
