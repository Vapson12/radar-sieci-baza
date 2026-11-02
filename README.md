# Radar Sieci – baza danych

Dane pobierane przez urządzenia **Radar Sieci** (audyt własnej sieci domowej na ESP32-2432S028).
Dzięki temu urządzenie nie potrzebuje karty SD, a baza znanych luk jest zawsze aktualna.

| Plik | Co zawiera | Kto z niego korzysta |
|---|---|---|
| `luki/index.txt` | Spis plików bazy luk i nazwy producentów. | Urządzenie czyta go najpierw. |
| `luki/<program>.txt` | Luki jednego programu (np. `openssh.txt`) – zakresy wersji, CVSS, KEV, EPSS. | Urządzenie pobiera tylko pliki programów znalezionych w sieci. |
| `luki/m_<producent>.txt` | Luki firmware routerów, kamer, NAS-ów i drukarek jednego producenta. | Jw. – tylko producenci obecni w sieci. |
| `luki/wszystko.txt` | Cała baza w jednym pliku. | Opcjonalnie na kartę SD jako `/luki.txt` (praca bez internetu). |
| `luki.txt` | Stary format bazy. | Firmware Radar Sieci 4.3 i starsze. |
| `skrypty/buduj_luki.py` | Buduje katalog `luki/` i `luki.txt`. | Automat GitHub Actions co miesiąc. |
| `skrypty/oui_dom.py` | Buduje `oui_dom.h` – producentów sprzętu domowego po adresie MAC. | Wbudowywany w program przy kompilacji. |
| `oui_dom.h` | Gotowy plik dla szkicu (ok. 11 tys. prefiksów, ok. 110 marek, 43 KB). | Kopiujesz do folderu szkicu `radar_sieci`. |

## Aktualizacja bazy luk

Automat **Aktualizuj bazę luk** (`.github/workflows/aktualizuj-luki.yml`) uruchamia się
2. dnia każdego miesiąca. Można go też uruchomić ręcznie: zakładka **Actions** →
**Aktualizuj bazę luk** → **Run workflow**.

Opcjonalnie: darmowy klucz NVD (https://nvd.nist.gov/developers/request-an-api-key)
dodany jako sekret repozytorium `NVD_API_KEY` znacznie przyspiesza budowanie bazy (bez klucza trwa ono kilkadziesiąt minut).

## Źródła

- CISA Known Exploited Vulnerabilities Catalog – luki wykorzystywane w atakach
- NIST National Vulnerability Database – zakresy wersji programów i firmware, ocena CVSS
- FIRST EPSS – prawdopodobieństwo wykorzystania luki w ciągu 30 dni
- IEEE Registration Authority – przydział prefiksów adresów MAC

Wykrywanie luk odbywa się po numerze wersji, dlatego urządzenie oznacza pewność wyniku:
**pewne** (wersja się zgadza), **prawdopodobne** (zgadza się tylko model) i **do sprawdzenia**
(np. OpenSSH z Ubuntu/Debiana – dystrybucje łatają luki bez zmiany numeru wersji).
