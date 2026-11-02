#!/usr/bin/env python3
"""
Buduje baze znanych luk dla modulu "Luki" w Radar Sieci.
Urzadzenia pobieraja ja z repozytorium przez HTTPS w trakcie skanu, wiec karta
SD nie jest potrzebna. W repozytorium baze odswieza automat GitHub Actions
(.github/workflows/aktualizuj-luki.yml) raz w miesiacu.

Zrodla:
  - CISA KEV - luki faktycznie wykorzystywane w atakach
  - NVD (NIST) - zakresy wersji podatnego oprogramowania i firmware, ocena CVSS
  - EPSS (FIRST) - prawdopodobienstwo uzycia luki w ataku w ciagu 30 dni

Recznie (Python 3.8+, bez dodatkowych pakietow):
    python skrypty/buduj_luki.py .
Opcjonalny klucz NVD (duzo szybciej): zmienna srodowiskowa NVD_API_KEY.

Pliki wynikowe (w podanym katalogu):
  luki/index.txt        spis plikow + aliasy producentow (urzadzenie czyta najpierw)
  luki/<program>.txt    reguly dla jednego programu (np. luki/openssh.txt)
  luki/m_<prod>.txt     reguly dla modeli jednego producenta (np. luki/m_tp-link.txt)
  luki/wszystko.txt     wszystko w jednym pliku - do skopiowania na karte SD jako /luki.txt
  luki.txt              stary format (dla firmware Radar Sieci 4.3 i starszych)

Format v2 (pola rozdzielone "|"):
  D|nazwa|alias1,alias2               producent i nazwy, pod ktorymi wystepuje
  V|klucz|op_od|wer_od|op_do|wer_do|CVE|CVSS|KEV|EPSS|opis
  M|producent|model|op_od|wer_od|op_do|wer_do|CVE|CVSS|KEV|EPSS|opis
  E|producent|model|wersje_sprzetu|zrodlo      model bez wsparcia producenta (EoL)
  (M bez zakresu wersji = dotyczy modelu niezaleznie od firmware;
   EPSS w procentach albo "-")
"""
import csv
import datetime
import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_KEY = os.environ.get("NVD_API_KEY", "").strip()
MIN_CVSS = 7.0          # mniej powazne luki pomijamy (chyba ze sa w KEV albo maja wysoki EPSS)
MIN_EPSS = 10.0         # [%] - luka z takim EPSS trafia do bazy mimo nizszego CVSS
MAX_DESC = 110
MAX_EXACT_PER_CVE = 8   # limit regul "dokladnie ta wersja" na jeden CVE i model (najnowsze)

# Producenci z ogromna liczba produktow niewidocznych w sieci (BIOS komputerow itp.):
# zostawiamy tylko linie produktow, ktore Radar Sieci rozpoznaje po sieci.
PRODUCT_FILTER = {
    "hp": r"laserjet|officejet|deskjet|pagewide|envy|designjet|smart_tank|photosmart|inkjet|mfp|printer|neverstop|tango",
}

# klucz w programie -> nazwy CPE w bazie NVD (typ:vendor:product)
PRODUCTS = {
    "openssh":    ["a:openbsd:openssh"],
    "dropbear":   ["a:dropbear_ssh_project:dropbear_ssh"],
    "lighttpd":   ["a:lighttpd:lighttpd"],
    "nginx":      ["a:f5:nginx", "a:nginx:nginx"],
    "apache":     ["a:apache:http_server"],
    "openssl":    ["a:openssl:openssl"],
    "php":        ["a:php:php"],
    "iis":        ["a:microsoft:internet_information_services"],
    "boa":        ["a:boa:boa"],
    "goahead":    ["a:embedthis:goahead"],
    "mini_httpd": ["a:acme:mini_httpd"],
    "thttpd":     ["a:acme:thttpd"],
    "rompager":   ["a:allegrosoft:rompager"],
    "vsftpd":     ["a:beasts:vsftpd", "a:vsftpd_project:vsftpd"],
    "proftpd":    ["a:proftpd:proftpd"],
    "miniupnpd":  ["a:miniupnp_project:miniupnpd"],
    "libupnp":    ["a:libupnp_project:libupnp", "a:pupnp_project:pupnp"],
    "jetty":      ["a:eclipse:jetty"],
    "exim":       ["a:exim:exim"],
    "filezilla_server": ["a:filezilla-project:filezilla_server"],
    "werkzeug":   ["a:palletsprojects:werkzeug"],
    "cups":       ["a:openprinting:cups", "a:apple:cups"],
    "mongoose":   ["a:cesanta:mongoose"],
}

# Producenci sprzetu domowego:
#   (plik, nazwa, producenci CPE w NVD (firmware), nazwy w opisach/OUI urzadzen)
# Pusta lista CPE = tylko wpisy z CISA KEV (sprzet firmowy, ogromne bazy w NVD).
DEVICE_VENDORS = [
    ("tp-link",   "TP-Link",         ["tp-link"],             ["tp-link", "tplink"]),
    ("d-link",    "D-Link",          ["dlink", "d-link"],     ["d-link", "dlink"]),
    ("netgear",   "NETGEAR",         ["netgear"],             ["netgear"]),
    ("zyxel",     "Zyxel",           ["zyxel"],               ["zyxel"]),
    ("hikvision", "Hikvision",       ["hikvision"],           ["hikvision"]),
    ("dahua",     "Dahua",           ["dahuasecurity"],       ["dahua"]),
    ("tenda",     "Tenda",           ["tenda"],               ["tenda"]),
    ("asus",      "ASUS",            ["asus"],                ["asus"]),
    ("linksys",   "Linksys",         ["linksys"],             ["linksys"]),
    ("qnap",      "QNAP",            ["qnap"],                ["qnap"]),
    ("synology",  "Synology",        ["synology"],            ["synology"]),
    ("ubiquiti",  "Ubiquiti",        ["ui", "ubiquiti"],      ["ubiquiti", "ubnt"]),
    ("mikrotik",  "MikroTik",        ["mikrotik"],            ["mikrotik", "routerboard", "routeros"]),
    ("huawei",    "Huawei",          ["huawei"],              ["huawei"]),
    ("zte",       "ZTE",             ["zte"],                 ["zte"]),
    ("xiaomi",    "Xiaomi",          ["mi", "xiaomi"],        ["xiaomi", "redmi"]),
    ("reolink",   "Reolink",         ["reolink"],             ["reolink"]),
    ("draytek",   "DrayTek",         ["draytek"],             ["draytek"]),
    ("totolink",  "TOTOLINK",        ["totolink"],            ["totolink"]),
    ("wd",        "Western Digital", ["western_digital", "wdc"], ["western digital", "my cloud"]),
    ("buffalo",   "Buffalo",         ["buffalo"],             ["buffalo"]),
    ("sagemcom",  "Sagemcom",        ["sagemcom"],            ["sagemcom"]),
    ("netis",     "Netis",           ["netis-systems"],       ["netis"]),
    ("edimax",    "Edimax",          ["edimax"],              ["edimax"]),
    ("trendnet",  "TRENDnet",        ["trendnet"],            ["trendnet"]),
    ("arris",     "Arris",           ["arris", "commscope"],  ["arris"]),
    ("technicolor", "Technicolor",   ["technicolor"],         ["technicolor", "thomson"]),
    ("avm",       "AVM",             ["avm"],                 ["avm", "fritz"]),
    ("teltonika", "Teltonika",       ["teltonika"],           ["teltonika"]),
    ("hp",        "HP",              ["hp"],                  ["hewlett", "hp inc"]),
    ("brother",   "Brother",         ["brother"],             ["brother"]),
    ("canon",     "Canon",           ["canon"],               ["canon"]),
    ("epson",     "Epson",           ["epson"],               ["epson"]),
    ("realtek",   "Realtek",         [],                      ["realtek"]),
    ("seagate",   "Seagate",         [],                      ["seagate"]),
    ("cisco",     "Cisco",           [],                      ["cisco"]),
    ("juniper",   "Juniper",         [],                      ["juniper"]),
    ("fortinet",  "Fortinet",        [],                      ["fortinet", "fortigate"]),
    ("sonicwall", "SonicWall",       [],                      ["sonicwall"]),
]


def clean(text: str, limit: int = MAX_DESC) -> str:
    text = text.encode("ascii", "ignore").decode()
    text = " ".join(text.replace("|", "/").split())
    return text[:limit]


def fetch(url: str, params: dict = None, nvd: bool = False) -> bytes:
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "Radar-Sieci-luki/2.0"}
    if nvd and API_KEY:
        headers["apiKey"] = API_KEY
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < 5:
                print(f"   serwer prosi o przerwe (HTTP {e.code}), czekam 30 s...")
                time.sleep(30)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < 5:
                print(f"   blad sieci ({e}), ponawiam za 15 s...")
                time.sleep(15)
                continue
            raise
    return b""


def get_json(url: str, params: dict = None, nvd: bool = False) -> dict:
    return json.loads(fetch(url, params, nvd).decode("utf-8"))


def load_epss() -> dict:
    """CVE -> EPSS w procentach. Pusty slownik, gdy zrodlo niedostepne."""
    try:
        raw = fetch(EPSS_URL)
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        out = {}
        rows = csv.reader(io.StringIO(raw.decode("utf-8", "ignore")))
        for row in rows:
            if len(row) >= 2 and row[0].startswith("CVE-"):
                try:
                    out[row[0]] = float(row[1]) * 100.0
                except ValueError:
                    pass
        return out
    except Exception as e:                                # EPSS jest dodatkiem
        print(f"   EPSS niedostepny ({e}) - pomijam")
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


def ranges(cve: dict, prefix: str, allow_all: bool = False):
    """Zakresy wersji z konfiguracji CPE. prefix np. "cpe:2.3:a:openbsd:openssh:".
    Zwraca slownik produkt -> zbior (op_od, wer_od, op_do, wer_do).
    allow_all: "wszystkie wersje" (*) zwracane jako pusty zakres."""
    out = {}
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                if not m.get("vulnerable") or not crit.startswith(prefix):
                    continue
                parts = crit.split(":")
                if len(parts) < 6:
                    continue
                product = parts[4]
                ver = parts[5]
                upd = parts[6] if len(parts) > 6 else "*"
                si, se = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                ei, ee = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if si or se or ei or ee:
                    if ver not in ("*", "-", ""):             # rzadkie: zakres + konkretna wersja
                        continue
                    start = (">=", si) if si else ((">", se) if se else ("", ""))
                    end = ("<=", ei) if ei else (("<", ee) if ee else ("", ""))
                    r = (start[0], start[1], end[0], end[1])
                elif ver not in ("*", "-", ""):
                    v = ver + (upd if upd not in ("*", "-", "") else "")
                    v = v.replace("\\", "")
                    r = (">=", v, "<=", v)
                elif allow_all:
                    r = ("", "", "", "")
                else:
                    continue                                  # "wszystkie wersje" - zbyt ogolne
                if any("|" in x for x in r):
                    continue
                out.setdefault(product, set()).add(r)
    return out


def nvd_cves(match: str):
    """Wszystkie CVE pasujace do CPE (z podzialem na strony)."""
    start, total, items = 0, None, []
    while total is None or start < total:
        data = get_json(NVD_URL, {"virtualMatchString": match,
                                  "resultsPerPage": 2000, "startIndex": start}, nvd=True)
        total = data.get("totalResults", 0)
        items += [v["cve"] for v in data.get("vulnerabilities", [])]
        start += 2000
        time.sleep(0.8 if API_KEY else 6.5)               # limit NVD
    return items


def epss_txt(epss: dict, cid: str) -> str:
    e = epss.get(cid)
    if e is None:
        return "-"
    return f"{e:.1f}" if e >= 0.1 else "0"


def important(score: float, in_kev: bool, ep: float) -> bool:
    return in_kev or score >= MIN_CVSS or ep >= MIN_EPSS


EOL_TEXT = re.compile(r"no longer supported by the maintainer|end[- ]of[- ]life|end[- ]of[- ]service|"
                      r"no longer (?:receives?|provides?) (?:security )?updates", re.I)
# CISA KEV: "The impacted product could be end-of-life (EoL) ... discontinue the utilization"
KEV_EOL = re.compile(r"end[- ]of[- ]life|\(EoL\)|end[- ]of[- ]service|discontinue the utilization", re.I)


def unsupported(cve: dict) -> bool:
    """CVE oznaczone jako dotyczace produktu bez wsparcia w chwili zgloszenia."""
    for t in cve.get("cveTags", []) or []:
        if "unsupported-when-assigned" in (t.get("tags") or []):
            return True
    return bool(EOL_TEXT.search(english(cve)))


def hw_versions(cve: dict, vendor: str, hw_product: str) -> set:
    """Wersje sprzetu (cpe:2.3:h:...) wymienione przy danym modelu, np. {"2.0", "3.0"}."""
    out = set()
    prefix = "cpe:2.3:h:" + vendor + ":" + hw_product + ":"
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                if crit.startswith(prefix):
                    v = crit.split(":")[5].replace("\\", "")
                    if v not in ("*", "-", "") and "|" not in v and "," not in v:
                        out.add(v)
    return out


def load_manual_eol(path: str) -> list:
    """Reczna lista: producent|model|wersje_sprzetu|zrodlo (linie z # pomijane)."""
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split("|")]
        if len(f) >= 2 and f[0] and f[1]:
            out.append((f[0], clean(f[1], 60).lower(), f[2] if len(f) > 2 else "",
                        clean(f[3], 40) if len(f) > 3 else "lista reczna"))
    return out


def model_name(product: str) -> str:
    """archer_c7_firmware -> archer c7"""
    p = re.sub(r"_firmware$", "", product)
    return clean(p.replace("_", " "), 60)


def write_lines(path: str, header: str, lines) -> int:
    with open(path, "w", encoding="ascii", newline="\n") as f:
        if header:
            f.write(header + "\n")
        for line in lines:
            f.write(line + "\n")
    return os.path.getsize(path)


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else "."
    base = (os.path.dirname(arg) or ".") if arg.endswith(".txt") else arg
    v1_path = arg if arg.endswith(".txt") else os.path.join(base, "luki.txt")
    out_dir = os.path.join(base, "luki")
    os.makedirs(out_dir, exist_ok=True)

    print("1/5 Pobieram liste CISA KEV...")
    kev = {v["cveID"]: v for v in get_json(KEV_URL).get("vulnerabilities", [])}
    print(f"    {len(kev)} aktywnie wykorzystywanych luk")

    print("2/5 Pobieram oceny EPSS...")
    epss = load_epss()
    print(f"    {len(epss)} ocen")

    print("3/5 Programy: zakresy wersji z NVD" + (" (z kluczem API)" if API_KEY else " (bez klucza - wolniej)"))
    prog = {}                 # klucz -> linie v2
    v1 = []                   # linie starego formatu
    scores = {}               # CVE -> CVSS (do wpisow KEV)
    warn = []
    for key, cpes in PRODUCTS.items():
        lines = set()
        for cp in cpes:
            prefix = "cpe:2.3:" + cp + ":"
            for cve in nvd_cves("cpe:2.3:" + cp):
                if cve.get("vulnStatus") == "Rejected":
                    continue
                cid = cve["id"]
                score = cvss(cve)
                scores[cid] = score
                in_kev = cid in kev
                if not important(score, in_kev, epss.get(cid, 0.0)):
                    continue
                desc = clean(english(cve))
                for rs in ranges(cve, prefix).values():
                    for so, sv, eo, ev in rs:
                        lines.add(f"V|{key}|{so}|{sv}|{eo}|{ev}|{cid}|{score:.1f}|{int(in_kev)}|{epss_txt(epss, cid)}|{desc}")
                        v1.append(f"V|{key}|{so}|{sv}|{eo}|{ev}|{cid}|{score:.1f}|{int(in_kev)}|{desc}")
        prog[key] = sorted(lines)
        print(f"    {key:<17} {len(lines):>5} regul")
        if not lines:
            warn.append(key)

    print("4/5 Firmware urzadzen z NVD (wedlug producenta)...")
    models = {}               # plik -> linie v2
    v1_models = []
    manual = load_manual_eol(os.path.join(os.path.dirname(os.path.abspath(__file__)), "eol_reczne.txt"))
    n_eol = 0
    for slug, name, cpe_vendors, _aliases in DEVICE_VENDORS:
        lines = set()
        have = set()          # (CVE) z zakresem wersji - nie dublujemy wpisem KEV
        eol = {}              # model -> [wersje sprzetu, zrodlo]
        for cv in cpe_vendors:
            prefix = "cpe:2.3:o:" + cv + ":"
            try:
                items = nvd_cves("cpe:2.3:o:" + cv)
            except Exception as e:
                print(f"    {name}: blad NVD ({e}) - pomijam")
                continue
            for cve in items:
                if cve.get("vulnStatus") == "Rejected":
                    continue
                cid = cve["id"]
                score = cvss(cve)
                scores[cid] = score
                in_kev = cid in kev
                if unsupported(cve):                      # model bez wsparcia (kazda luka, nie tylko powazna)
                    for product in ranges(cve, prefix, allow_all=True):
                        if not product.endswith("_firmware"):
                            continue
                        if slug in PRODUCT_FILTER and not re.search(PRODUCT_FILTER[slug], product):
                            continue
                        model = model_name(product)
                        if not re.search(r"\d", model) and len(model.split()) < 2:
                            continue
                        e = eol.setdefault(model, [set(), cid])
                        e[0] |= hw_versions(cve, cv, re.sub(r"_firmware$", "", product))
                if not important(score, in_kev, epss.get(cid, 0.0)):
                    continue
                desc = clean(english(cve))
                for product, rs in ranges(cve, prefix, allow_all=True).items():
                    if not product.endswith("_firmware"):
                        continue                          # tylko firmware sprzetu
                    if slug in PRODUCT_FILTER and not re.search(PRODUCT_FILTER[slug], product):
                        continue
                    model = model_name(product)
                    if not re.search(r"\d", model) and len(model.split()) < 2:
                        continue                          # zbyt ogolna nazwa
                    exact = [r for r in rs if r[0] == ">=" and r[2] == "<=" and r[1] == r[3]]
                    other = [r for r in rs if r not in exact]
                    exact.sort(key=lambda r: [(0, int(t)) if t.isdigit() else (1, t) for t in re.findall(r"\d+|[a-z]+", r[1].lower())])
                    for so, sv, eo, ev in other + exact[-MAX_EXACT_PER_CVE:]:
                        lines.add(f"M|{name}|{model}|{so}|{sv}|{eo}|{ev}|{cid}|{score:.1f}|{int(in_kev)}|{epss_txt(epss, cid)}|{desc}")
                    have.add(cid)
        # wpisy z KEV (bez wersji) dla tego producenta
        for cid, v in kev.items():
            vendor = v.get("vendorProject", "").lower()
            if vendor != name.lower() and vendor not in cpe_vendors:
                continue
            desc = clean(v.get("vulnerabilityName", "") or v.get("shortDescription", ""))
            product = clean(v.get("product", ""), 60)
            v1_models.append(f"M|{clean(v.get('vendorProject', ''), 40)}|{product}|{cid}|-|1|{desc}")
            if cid in have:
                continue
            sc = scores.get(cid, 0.0)
            lines.add(f"M|{name}|{product}|||||{cid}|{sc:.1f}|1|{epss_txt(epss, cid)}|{desc}")
            # CISA: "produkt moze byc EoL - przestan go uzywac"
            if KEV_EOL.search(v.get("requiredAction", "") + " " + v.get("notes", "")) and \
                    (re.search(r"\d", product) or len(product.split()) >= 2):
                eol.setdefault(product.lower(), [set(), cid])
        for m_vendor, model, hw, src in manual:
            if m_vendor.lower() == name.lower():
                e = eol.setdefault(model, [set(), src])
                e[0] |= {h.strip() for h in hw.split(",") if h.strip()}
                e[1] = src
        for model, (hw, src) in eol.items():
            hw_txt = ",".join(sorted(hw))[:60]
            lines.add(f"E|{name}|{model}|{hw_txt}|{src}")
        n_eol += len(eol)
        models[slug] = sorted(lines)
        print(f"    {name:<17} {len(lines):>5} regul")

    print("5/5 Zapisuje pliki...")
    today = datetime.date.today().isoformat()
    n_v = sum(len(x) for x in prog.values())
    n_m = sum(len(x) for x in models.values())
    head = f"# baza {today} | KEV {len(kev)} | wersje {n_v} | modele {n_m} | EPSS {'tak' if epss else 'nie'} | v2"
    d_lines = [f"D|{name}|{','.join(aliases)}" for slug, name, _c, aliases in DEVICE_VENDORS]

    # stare pliki programow/producentow, ktorych juz nie ma
    for fn in os.listdir(out_dir):
        if fn.endswith(".txt"):
            os.remove(os.path.join(out_dir, fn))

    index = [head]
    for key, lines in prog.items():
        if lines:
            write_lines(os.path.join(out_dir, key + ".txt"), head, lines)
            index.append(f"P|{key}|{len(lines)}")
    for slug, name, _c, aliases in DEVICE_VENDORS:
        lines = models.get(slug, [])
        if lines:
            write_lines(os.path.join(out_dir, "m_" + slug + ".txt"), head, lines)
            index.append(f"F|{slug}|{name}|{','.join(aliases)}|{len(lines)}")
    write_lines(os.path.join(out_dir, "index.txt"), "", index)

    all_lines = d_lines + [l for x in prog.values() for l in x] + [l for x in models.values() for l in x]
    size_all = write_lines(os.path.join(out_dir, "wszystko.txt"), head, all_lines)

    v1 = sorted(set(v1))
    v1_models = sorted(set(v1_models))
    write_lines(v1_path, f"# baza {today} | KEV {len(kev)} | wersje {len(v1)} | modele {len(v1_models)}",
                v1 + v1_models)

    print(f"Modele bez wsparcia producenta: {n_eol}")
    print(f"\nZapisano {out_dir}/: programy {n_v} regul, modele {n_m} regul, "
          f"wszystko.txt {size_all // 1024} KB")
    if warn:
        print("Uwaga: brak wynikow dla: " + ", ".join(warn) +
              " - sprawdz nazwe CPE w slowniku PRODUCTS (https://nvd.nist.gov/products/cpe/search)")
    print("Gotowe. Na karte SD skopiuj luki/wszystko.txt jako /luki.txt (opcjonalnie).")


if __name__ == "__main__":
    main()
