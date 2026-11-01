# Radar Sieci – baza danych

Dane pobierane przez urządzenia **Radar Sieci** (audyt własnej sieci domowej na ESP32-2432S028).
Dzięki temu urządzenie nie potrzebuje karty SD, a baza znanych luk jest zawsze aktualna.

| Plik | Co zawiera | Kto z niego korzysta |
|---|---|---|
| `luki.txt` | Znane luki w oprogramowaniu routerów, kamer, NAS-ów i innych urządzeń domowych (CISA KEV + NVD). | Urządzenie pobiera go przez HTTPS w module **Luki** i w **Szybkim audycie**. |
| `skrypty/buduj_luki.py` | Buduje `luki.txt`. | Automat GitHub Actions co miesiąc. |
| `skrypty/oui_dom.py` | Buduje `oui_dom.h` – producentów sprzętu domowego po adresie MAC. | Wbudowywany w program przy kompilacji. |
| `oui_dom.h` | Gotowy plik dla szkicu (ok. 11 tys. prefiksów, ok. 110 marek, 43 KB). | Kopiujesz do folderu szkicu `radar_sieci`. |

## Aktualizacja bazy luk

Automat **Aktualizuj bazę luk** (`.github/workflows/aktualizuj-luki.yml`) uruchamia się
2. dnia każdego miesiąca. Można go też uruchomić ręcznie: zakładka **Actions** →
**Aktualizuj bazę luk** → **Run workflow**.

Opcjonalnie: darmowy klucz NVD (https://nvd.nist.gov/developers/request-an-api-key)
dodany jako sekret repozytorium `NVD_API_KEY` przyspiesza pobieranie z ok. 10 min do ok. 1 min.

## Źródła

- CISA Known Exploited Vulnerabilities Catalog – luki wykorzystywane w atakach
- NIST National Vulnerability Database – zakresy wersji i ocena CVSS
- IEEE Registration Authority – przydział prefiksów adresów MAC

Wykrywanie luk odbywa się po numerze wersji, więc wynik oznacza „możliwą lukę” –
producent mógł ją załatać bez zmiany numeru wersji.
