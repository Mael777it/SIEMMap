<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/siemmap-logo-dark.svg">
    <img src="assets/siemmap-logo.svg" alt="SIEMMap" width="420">
  </picture>
</p>

<p align="center">
  Lokalna aplikacja do mapowania pokrycia źródeł logów <b>SIEM</b>: inwentarz serwerów i urządzeń, pakiety logowania<br>
  <b>typ urządzenia → rola → co logować</b> oraz gotowe konfiguracje dla <b>Splunka, Wazuha i Elastica</b>. Jeden plik HTML, bez serwera, dane w zaszyfrowanym sejfie.
</p>

<p align="center">
  <img alt="Licencja MIT" src="https://img.shields.io/badge/licencja-MIT-1D5E6E">
  <img alt="Wersja" src="https://img.shields.io/badge/wersja-3.4-172226">
  <a href="https://github.com/mael777it/SIEMMap"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-mael777it%2FSIEMMap-172226?logo=github"></a>
</p>

---

## Pliki

| Plik | Opis |
|---|---|
| `siemmap.html` | Aplikacja. Otwierasz ją w Chrome, Edge albo Firefoksie. Katalog urządzeń, ról i konfiguracji jest wbudowany. |
| `siemmap-import-szablon.csv` | Przykładowy plik do masowego importu hostów (separator `;`, dane fikcyjne). |
| `decrypt_vault.py` | Awaryjne odczytanie kopii sejfu bez przeglądarki. Wymaga `pip install cryptography`. |
| `assets/` | Logo (wersja jasna, ciemna i sam znak). |

## Praca

1. **Pierwsze uruchomienie:** na starcie widać dane demonstracyjne. **Utwórz sejf** zakłada konto administratora i szyfrowaną bazę w przeglądarce (AES-256-GCM, klucz konta z PBKDF2-SHA256, 1 000 000 iteracji, losowa sól). Opcjonalnie włączasz **plik klucza** jako drugi czynnik.
2. **Inwentarz:** wyszukiwarka i filtry dla tysięcy hostów, zaznaczanie zbiorcze, pokrycie P1 i luki dla każdego hosta. Host dodajesz ręcznie albo importem CSV.
3. **Katalog:** wybierasz **typ urządzenia** (42 typy) i **role** (142), a aplikacja składa pakiet: co logować (543 pozycje z priorytetem P1–P3, wolumenem i MITRE ATT&CK), czego nie logować, na co uważać, test po wdrożeniu i detekcje startowe.
4. **Profil zbierania:** *Minimum* (tylko P1), *Zalecany* (P1 + P2 i tanie P3) albo *Maksymalny* (wszystko o wartości detekcyjnej lub śledczej). Profil zmienia listę pozycji i generowane konfiguracje.
5. **Konfiguracje:** `inputs.conf` (Splunk UF), `agent.conf` + `local_rules.xml` (Wazuh), `winlogbeat.yml` / `filebeat.yml` (Elastic) oraz przygotowanie hosta lub urządzenia (auditpol, auditd, CLI). Widok **Gotowy plik** pokazuje scalony plik dla podstawy i wszystkich wybranych ról. **Pobierz pakiet (.zip)** zawiera README i konfiguracje we wszystkich trzech profilach. Każdą warstwę możesz zastąpić własnym plikiem.
6. **Stan zbierania:** dla każdej pozycji oznaczasz *Zbierane*, *Częściowo*, *Brak* albo *Nie dotyczy* – na jednym hoście albo zbiorczo na wszystkich hostach danego typu i roli – oraz datę weryfikacji.
7. **Konta i dziennik zmian:** role *administrator*, *edytor*, *podgląd*. Każda zmiana trafia do dziennika z łańcuchem skrótów SHA-256, który wykrywa edycję wpisów. Po 30 minutach bezczynności aplikacja się blokuje.

## Katalog urządzeń

| Grupa | Typy |
|---|---|
| Serwery i stacje | Windows Server, stacje Windows, macOS, Linux, systemy legacy |
| Sieć przewodowa | Cisco, HPE Aruba / ProCurve / Comware, MikroTik, inne (Juniper, Huawei…), SD-WAN, DDI |
| Wi-Fi | Ubiquiti UniFi, inne kontrolery i AP |
| Firewalle, VPN, proxy, NAC | Palo Alto, FortiGate, Cisco ASA/FTD, Check Point / Sophos / pfSense, ADC, proxy, NAC, bramki poczty, CDN/WAF |
| Wirtualizacja, sprzęt, backup, PKI | VMware, Proxmox / Nutanix, BMC (iDRAC, iLO), backup, HSM / PKI |
| Chmura, SaaS i tożsamość | Entra ID / M365, Okta, Google Workspace, MFA, MDM, IaaS (AWS, Azure, GCP) |
| Aplikacje, DevOps i narzędzia IT | DevOps, VDI, MFT, narzędzia IT i bezpieczeństwa, VoIP |
| OT, IoT i bezpieczeństwo fizyczne | OT/ICS, SKD i CCTV, UPS / BMS, IoT, drukarki |
| Dane i aplikacje biznesowe | bazy danych i NoSQL, SAP, Atlassian, CRM, POS |

## Import hostów (CSV)

Kolumny: `ip; hostname; type; roles; tier; env; os; location; owner; siem; method; index; retention_days; gb_per_day; verified; tags; note`.

- Klucz walidacji to **adres IP**, zapasowo **hostname**. Przed zapisem aplikacja pokazuje podgląd: nowe, aktualizacje, bez zmian, duble w pliku, konflikty i błędy.
- Role oddzielasz znakiem `|` (np. `dc|dns`). Pełną listę typów i ról z legendą pobierzesz w aplikacji: **Importuj → Szablon + legenda (.zip)**.

## Odczyt sejfu poza przeglądarką

```
pip install cryptography
python3 decrypt_vault.py siemmap-sejf-2026-09-20.json               # podsumowanie
python3 decrypt_vault.py siemmap-sejf-2026-09-20.json -k SIEMMap-klucz-<login>.json
python3 decrypt_vault.py siemmap-sejf-2026-09-20.json --csv hosty.csv
```

Kopię sejfu robisz przyciskiem **Eksportuj → Pobierz zaszyfrowany .json**.

## Bezpieczeństwo danych

- Dane zostają w przeglądarce (localStorage) i nigdzie nie są wysyłane. **Regularnie rób zaszyfrowaną kopię** – wyczyszczenie danych przeglądarki usuwa sejf.
- Role są egzekwowane przez aplikację. Każde konto zna klucz danych, więc rola nie chroni przed osobą, która ma hasło i zmodyfikuje kod strony.
- **Repozytorium zawiera wyłącznie kod.** `.gitignore` wyklucza kopie sejfu, pliki kluczy, eksporty jawne, listy hostów i pobrane pakiety. Nie commituj danych żadnej organizacji.
- Szablony konfiguracji to punkt wyjścia. Sprawdź je na hostach testowych (`splunk btool check`, `wazuh-logtest`, `filebeat test config`), zanim wdrożysz je na całą flotę.

## Autor i licencja

**SIEMMap** – autor i twórca: **Marcin Lewandowski** ([@mael777it](https://github.com/mael777it)).
Repozytorium: https://github.com/mael777it/SIEMMap
Udostępnione na licencji [MIT](LICENSE) – możesz używać, modyfikować i rozpowszechniać, także komercyjnie, zachowując informację o prawach autorskich.

Logotyp korzysta z kroju IBM Plex Sans Condensed (SIL Open Font License 1.1), zamienionego na krzywe.
