# Shadowborn — punkt wejścia

Rozszerzenia względem Mistborna są śledzone w [pełnej macierzy funkcji](mistborn-parity.md).
Dodano natywne blokowanie domen (także listy `hosts`), wyjątki DNS, prywatne nazwy
usług i blokowanie docelowych adresów IPv4 w stylu Coppercloud. Ustawienia nie
tworzą historii zapytań ani ruchu: [instrukcja filtrów](filtering.md).
Panel WWW/MFA i aplikacje dodatkowe pozostają do wdrożenia; samo umieszczenie ich
w macierzy nie oznacza, że działają. Oryginalne moduły rejestrujące aktywność
kolidują z obowiązkową polityką „zero logów”.

Repozytorium zawiera nowy moduł przygotowywania serwera WireGuard oraz zachowany
klient Shadow Mist. Nowy CLI generuje konfigurację serwera, zarządza urządzeniami
przed wdrożeniem i przygotowuje chronione kopie. Nie uruchamia automatycznie VPN.

Nowe `shadowborn setup` przygotowuje w jednym katalogu konfigurację serwera,
stan autoryzacji oraz zaszyfrowany profil i QR pierwszego urządzenia. Wymaga
podania IP serwera, interfejsu WAN, zakresu administratora SSH i publicznego
klucza age do szyfrowania eksportów. Najpierw użyj `--dry-run`. Pełna instrukcja:
[serwer i połączenie przez QR](quickstart-qr.md).

QR zawiera prywatny klucz urządzenia: odszyfruj go i wyświetl lokalnie na zaufanym
komputerze, a następnie zeskanuj aplikacją WireGuard. Osobne urządzenie dostaje
osobny profil i PSK. Klucz prywatny klienta nie jest zapisywany w stanie serwera;
wygodny eksport wymaga świadomego `--accept-server-key-generation`.

Polityka „zero logów” zabrania historii DNS, połączeń i ruchu w komponentach
Shadowborn. Nie wyłącza globalnych logów systemu i nie obejmuje zapisów operatora
VPS czy ISP. Zgodność usług w czasie pracy i po restarcie nadal wymaga testów VM.
DNS klient–serwer jest szyfrowany przez WireGuard; Unbound przygotowano do
przesyłania zapytań dalej przez DoT. Pi-hole pozostaje kolejnym etapem po działającym
tunelu i testach braku historii: [plan DNS/Pi-hole](dns-privacy.md#optional-pi-hole-after-the-core-vpn).

Instrukcje techniczne są po angielsku: [serwer](installation-server.md),
[klient](client-enrollment.md), [odzyskiwanie](admin-recovery.md),
[polityka bez historii aktywności](no-logs-policy.md), [testy](validation.md).
Tryb strict, automatyczny rollback sieci i obsługa urządzeń na działającym serwerze
pozostają niewdrożone. To nie jest gotowe wydanie produkcyjne ani gwarancja
anonimowości. Dotychczasowy klient ma osobny [poradnik Shadow Mist](legacy/README.md).
