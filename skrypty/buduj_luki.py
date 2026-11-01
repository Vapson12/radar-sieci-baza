#!/usr/bin/env python3
"""
Buduje luki.txt - baze znanych luk dla modulu "Luki" w Radar Sieci.
Urzadzenia pobieraja ten plik z repozytorium przez HTTPS w trakcie skanu,
wiec karta SD nie jest potrzebna. W repozytorium plik odswieza automat
GitHub Actions (.github/workflows/aktualizuj-luki.yml) raz w miesiacu.

Zrodla:
  - CISA KEV - luki faktycznie wykorzystywane w atakach
  - NVD (NIST) - zakresy wersji podatnego oprogramowania i ocena CVSS

Recznie (Python 3.8+, bez dodatkowych pakietow):
    python skrypty/buduj_luki.py luki.txt
Opcjonalny klucz NVD (szybciej): zmienna srodowiskowa NVD_API_KEY.

Format (jedna regula w linii, pola rozdzielone "|"):
  # naglowek (data, liczby regul)
  V|klucz|op_od|wersja_od|op_do|wersja_do|CVE|CVSS|KEV(0/1)|opis
  M|producent|model|CVE|CVSS|KEV|opis
"""
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ.get("NVD_API_KEY", "").strip()
MIN_CVSS = 7.0          # mniej powazne luki pomijamy (chyba ze sa w KEV)
MAX_DESC = 110

# klucz w programie -> nazwy CPE w bazie NVD (vendor:product)
PRODUCTS = {
    "openssh":    ["openbsd:openssh"],
    "dropbear":   ["dropbear_ssh_project:dropbear_ssh"],
    "lighttpd":   ["lighttpd:lighttpd"],
    "nginx":      ["f5:nginx", "nginx:nginx"],
    "apache":     ["apache:http_server"],
    "openssl":    ["openssl:openssl"],
    "php":        ["php:php"],
    "iis":        ["microsoft:internet_information_services"],
    "boa":        ["boa:boa"],
    "goahead":    ["embedthis:goahead"],
    "mini_httpd": ["acme:mini_httpd"],
    "thttpd":     ["acme:thttpd"],
    "rompager":   ["allegrosoft:rompager"],
    "vsftpd":     ["beasts:vsftpd", "vsftpd_project:vsftpd"],
    "proftpd":    ["proftpd:proftpd"],
    "miniupnpd":  ["miniupnp_project:miniupnpd"],
    "libupnp":    ["libupnp_project:libupnp", "pupnp_project:pupnp"],
    "jetty":      ["eclipse:jetty"],
}

# producenci sprzetu domowego - ich wpisy z KEV trafiaja do regul "M"
DEVICE_VENDORS = [
    "TP-Link", "D-Link", "NETGEAR", "Zyxel", "Hikvision", "Dahua", "Tenda", "ASUS",
    "Linksys", "QNAP", "Synology", "Ubiquiti", "MikroTik", "Huawei", "ZTE", "Xiaomi",
    "Reolink", "DrayTek", "TOTOLINK", "Western Digital", "Buffalo", "Realtek",
    "Sagemcom", "Netis", "Edimax", "Cisco", "Juniper", "Fortinet", "SonicWall",
    "Seagate", "TRENDnet", "Arris", "Technicolor", "AVM", "Teltonika",
]


def clean(text: str, limit: int = MAX_DESC) -> str:
    text = text.encode("ascii", "ignore").decode()
    text = " ".join(text.replace("|", "/").split())
    return text[:limit]


def get_json(url: str, params: dict = None, nvd: bool = False) -> dict:
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "Radar-Sieci-luki/1.0"}
    if nvd and API_KEY:
        headers["apiKey"] = API_KEY
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < 5:
                print(f"   serwer prosi o przerwe (HTTP {e.code}), czekam 30 s...")
                time.sleep(30)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < 5:
                print(f"   blad sieci ({e}), ponawiam za 10 s...")
                time.sleep(10)
                continue
            raise
    return {}


def cvss(cve: dict) -> float:
    m = cve.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            try:
                return float(m[k][0]["cvssData"]["baseScore"])
            except (KeyError, ValueError, IndexError):
                pass
    return 0.0


def english(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def ranges(cve: dict, vp: str):
    """Zakresy wersji z konfiguracji CPE dla danego vendor:product."""
    prefix = "cpe:2.3:a:" + vp + ":"
    out = set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable") or not m.get("criteria", "").startswith(prefix):
                    continue
                parts = m["criteria"].split(":")
                ver = parts[5] if len(parts) > 5 else "*"
                upd = parts[6] if len(parts) > 6 else "*"
                si, se = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                ei, ee = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if si or se or ei or ee:
                    start = (">=", si) if si else ((">", se) if se else ("", ""))
                    end = ("<=", ei) if ei else (("<", ee) if ee else ("", ""))
                    if ver not in ("*", "-", ""):        # rzadkie: zakres + konkretna wersja
                        continue
                elif ver not in ("*", "-", ""):
                    v = ver + (upd if upd not in ("*", "-", "") else "")
                    start, end = (">=", v), ("<=", v)
                else:
                    continue                              # "wszystkie wersje" - zbyt ogolne
                out.add((start[0], start[1], end[0], end[1]))
    return out


def nvd_product(vp: str):
    """Wszystkie CVE dla vendor:product (z podzialem na strony)."""
    start, total, items = 0, None, []
    while total is None or start < total:
        data = get_json(NVD_URL, {"virtualMatchString": "cpe:2.3:a:" + vp,
                                  "resultsPerPage": 2000, "startIndex": start}, nvd=True)
        total = data.get("totalResults", 0)
        items += [v["cve"] for v in data.get("vulnerabilities", [])]
        start += 2000
        time.sleep(0.8 if API_KEY else 6.5)               # limit NVD
    return items


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "luki.txt"
    print("1/3 Pobieram liste CISA KEV...")
    kev = {v["cveID"]: v for v in get_json(KEV_URL).get("vulnerabilities", [])}
    print(f"    {len(kev)} aktywnie wykorzystywanych luk")

    lines_v, warn = [], []
    print("2/3 Pobieram zakresy wersji z NVD" + (" (z kluczem API)" if API_KEY else " (bez klucza - wolniej)"))
    for key, vps in PRODUCTS.items():
        count = 0
        for vp in vps:
            for cve in nvd_product(vp):
                if cve.get("vulnStatus") == "Rejected":
                    continue
                cid = cve["id"]
                score = cvss(cve)
                in_kev = cid in kev
                if score < MIN_CVSS and not in_kev:
                    continue
                desc = clean(english(cve))
                for so, sv, eo, ev in ranges(cve, vp):
                    lines_v.append(f"V|{key}|{so}|{sv}|{eo}|{ev}|{cid}|{score:.1f}|{int(in_kev)}|{desc}")
                    count += 1
        print(f"    {key:<11} {count:>5} regul")
        if count == 0:
            warn.append(key)

    print("3/3 Modele urzadzen z listy KEV...")
    lines_m = []
    vendors = [v.lower() for v in DEVICE_VENDORS]
    for cid, v in kev.items():
        vendor = v.get("vendorProject", "")
        if vendor.lower() not in vendors:
            continue
        desc = clean(v.get("vulnerabilityName", "") or v.get("shortDescription", ""))
        lines_m.append(f"M|{clean(vendor, 40)}|{clean(v.get('product', ''), 60)}|{cid}|-|1|{desc}")
    print(f"    {len(lines_m)} regul dla modeli urzadzen")

    lines_v = sorted(set(lines_v))
    lines_m = sorted(set(lines_m))
    today = datetime.date.today().isoformat()
    with open(out_path, "w", encoding="ascii", newline="\n") as f:
        f.write(f"# baza {today} | KEV {len(kev)} | wersje {len(lines_v)} | modele {len(lines_m)}\n")
        for line in lines_v + lines_m:
            f.write(line + "\n")
    size = os.path.getsize(out_path)
    print(f"\nZapisano {out_path}: {len(lines_v) + len(lines_m)} regul, {size // 1024} KB")
    if warn:
        print("Uwaga: brak wynikow dla: " + ", ".join(warn) +
              " - sprawdz nazwe CPE w slowniku PRODUCTS (https://nvd.nist.gov/products/cpe/search)")
    print("Gotowe.")


if __name__ == "__main__":
    main()
