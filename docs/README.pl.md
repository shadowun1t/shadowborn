# Shadowborn — punkt wejścia

Rozszerzenia względem Mistborna są śledzone w [pełnej macierzy funkcji](mistborn-parity.md).
Dodano natywne blokowanie domen (także listy `hosts`), wyjątki DNS, prywatne nazwy
usług i blokowanie docelowych adresów IPv4 w stylu Coppercloud. Ustawienia nie
tworzą historii zapytań ani ruchu: [instrukcja filtrów](filtering.md).
Panel WWW/MFA i aplikacje dodatkowe pozostają do wdrożenia; samo umieszczenie ich
w macierzy nie oznacza, że działają. Oryginalne moduły rejestrujące aktywność
kolidują z obowiązkową polityką „zero logów”.

Shadowborn to brama WireGuard na własnym VPS. Serwer można aktywować po sprawdzeniu
konsoli poleceniem `sudo shadowborn apply --console-verified --confirm`. Operator
ma 120 sekund na sprawdzenie DNS i adresu wyjściowego z urządzenia oraz zatwierdzenie
transakcji. Po zatwierdzeniu serwer obsługuje dodawanie i odwoływanie urządzeń
podczas pracy. [Instalacja serwera](installation-server.md).

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
VPS czy ISP. Na maszynach x86_64 z Debianem 13 i Ubuntu 24.04 sprawdzono
dzienniki procesów usług i pliki projektu po ruchu testowym, awarii DNS,
odwołaniu urządzenia i restarcie. Dzienniki objęte testem były puste.
DNS klient–serwer przechodzi przez WireGuard, a Unbound przekazuje zapytania
dalej przez uwierzytelniony DoT. Integracja Pi-hole wymaga osobnego sprawdzenia.
[Zakres testów](validation.md) i [plan DNS/Pi-hole](dns-privacy.md#optional-pi-hole-after-the-core-vpn).

Instrukcje techniczne są po angielsku: [serwer](installation-server.md),
[klient](client-enrollment.md), [odzyskiwanie](admin-recovery.md),
[polityka bez historii aktywności](no-logs-policy.md), [testy](validation.md).
Dotychczasowy klient ma osobny [poradnik Shadow Mist](legacy/README.md).

## Szyfrowany DNS i ochrona klienta

Działa opcjonalny upstream DoH przez dnscrypt-proxy, z przypiętym adresem IPv4 i
weryfikacją certyfikatu. Konfiguracja: `shadowborn dns configure --stamp-file
/root/upstream.stamp --confirm`, a następnie ponowny `render`. Nowy `setup`
przyjmuje też `--dnscrypt-stamp`. Domyślnie pozostaje Quad9 DoT.

Na osobnym kliencie Linux zainstaluj profil `--strict` i pakiet
`scripts/install-client-lockdown.sh`. Z konsoli wykonaj `shadowborn-client-lockdown
plan`, rozpocznij próbę z `enable --console-verified --confirm`, uruchom
WireGuard i sprawdź DNS oraz adres VPS. Polecenie `commit` utrwala zależność
startu sieci od zapory. Wygaśnięcie próby przywraca dostęp bezpośredni.
[Instrukcja klienta](client-kill-switch.md) i [wyniki testów](validation.md).
