## Ogólne informacje

Skrypt służy do przesyłania plików '.xml' przy pomocy interfejsu API i ich odpowiedniej segregacji w zależności od statusu żądania.

Dla wszystkich plików o danym rozszerzeniu znajdujących się we wskazanej lokalizacji są podejmowane próby wysyłki na wskazany adres. W zalezności od statusu, pliki te se są segregowane na pliki wysłane poprawnie oraz niepoprawnie. Powód niepowodzenia wysyłki jest zapisywany w pliku .txt.
Skrypt działa w sposób synchroniczny w celu minimalizacji obciążenia serwisów do autentykacji i uwierzytelniania oraz serwisu docelowego.

## Konfiguracja

Plik konfiguracyjny 'config.ini' znajduje się w folderze /pwdp/config/. Zawiera on informacje dotyczące parametrów wykonania skryptu, danych użytkownika oraz ścieżek roboczych.

Parametry:
```
[General]
scanning_mode = one-time / loop                                                                         # Tryb wykonywania skryptu - na żadanie lub ciągły.
delay_in_seconds = 2                                                                                    # Opóźnienie pomiędzy obsługą poszczególnych plików w sekundach.
upload_endpoint = https://pwdpb.spsm-sr.pse.pl/pwdp/pwdp-api/oze/schedule-request-files                 # Endpoint do upload'u plików
oauth2_endpoint = https://sduext-sso.spsm-sr.pse.pl/auth/realms/SDU-EXT/protocol/openid-connect/token   # Endpoint do uwierzytelniania i autentykacji przy pomocy żetonów JWT.

file_format = .xml                                                                                      # Rozszrzenie definiujące pliki, które mają być procesowane

[Credentials]
user = nazwa.uzytkownika@pse.pl                                                                         # Login dla użytkownika wykorzystywanego w procesie.
secret = jakieshaslo!                                                                                   # Hasło dla użytkownika wykorzystywanego w procesie.
permission = 10368                                                                                      # Numer uprawnień dla użytkownika. Odpowiedni numer pozwala wykorzystać 'upload_endpoint'.

[Paths]
source_path = C:/DEV/Projekty/PWDP/folder_z_xml                                                         # Ścieżka, w której znajdują się pliki '.xml' do wysłania.
sent_dir_path = C:/DEV/Projekty/PWDP/folder_z_xml/sent                                                  # Ścieżka, w której przechowywane są pliki wysłane z powodzeniem.

failed_dir_name = C:/DEV/Projekty/PWDP/folder_z_xml/failed                                              # Ścieżka, w której przechowywane są pliki których nie udało się przesłać. W folderze tym tworzone są również pliki informujące o błędach podczas próby wysłania.
```

## Uruchomienie

Uruchomić plik main.py z poziomu katalogu projketu np.:
```
python -m main
```

## Autentykacja i Autoryzacja

Autentykacja i autoryzacja przeprowadzana jest przy pomocy serwisu PPB oraz PWDP. Wykorzystywane są żetony JWT, podstawowy i docelowy.
1. Żeton podstawowy pobierany jest z serwisu PPB przy wykorzystaniu danych użytkownika (login/hasło).
2. Żeton docelowy pobierany jest z serwisu PPB przy wykorzystaniu żetonu podstawowego oraz kodu uprawnień.
3. Żeton docelowy wykorzystywany jest przy wysyłaniu plików '.xml' do serwisu PWDP wraz z kodem uprawnień.

Przykładowe żądania:
1. Pobranie żetonu podstawowego z serwisu PPB
```
curl --insecure -d "grant_type=password" -d "client_id=frontend-ppb" \
-d username={nazwa.uzytkownika@pse.pl} \
-d "password={jakieshaslo} \
https://sduext-sso.spsm-sr.pse.pl/auth/realms/SDU-EXT/protocol/openid-connect/token
```

gdzie:
- {nazwa.uzytkownika@pse.pl} Identyfikator klienta
- {jakieshaslo} Hasło klienta

Przykładowa odpowiedź to format JSON:
```
{
    "access_token":"eyJhbG...",
    "expires_in":1800,
    "refresh_expires_in":3600,
    "refresh_token":"eyJhbG...",
    "token_type":"Bearer",
    "not-before-policy":0,
    "session_state":"240bb03a-9e33-42f0-a29c-6a7241b0d88e",
    "scope":"email profile"
}

```

2. Pobranie żetonu docelowego z serwisu PPB
```
curl --insecure --header 'Authorization: Bearer eyJHbG...' -- header 'Content-Type: application/x-www-form-urlencoded' \
-d grant_type=urn:ietf:params:oauth:grant-type:uma-ticket \
-d 'audience: pwdp2,
-d 'permission: {kod_uprawnień}' \
https://sduext-sso.spsm-sr.pse.pl/auth/realms/SDU-EXT/protocol/openid-connect/token
```

gdzie:
- {kod_uprawnień} Kod uprawnień użytkownika
- Bearer ey........... żeton podstawowy uzyskany z serwisu PPB

Przykładowa odpowiedź to format JSON:
```
{
    'upgraded': False,
    'access_token': 'eyJhbGc...',
    'expires_in': 1800,
    'refresh_expires_in': 3582,
    'refresh_token': 'eyJhbGciOi...',
    'token_type': 'Bearer',
    'not-before-policy': 0
}
```

3. Wysłanie pliku do serwisu PWDP
```
curl --location --request POST 'https://pwdpb.spsm-sr.pse.pl/pwdp/pwdp-api/oze/schedule-request-files' \
--header 'Content-Type: multipart/form-data' \
--header 'Resource: {kod_uprawnień}' \
--header 'Authorization: Bearer eyJhbGci...' \
--form 'file=@"{sciezka_do_pliku}"'
```

gdzie:
- {kod_uprawnień} Kod uprawnień użytkownika
- Bearer ey........... żeton docelowy uzyskany z serwisu PPB
- {sciezka_do_pliku} Lokaliacja pliku do wysłania

Przykładowa odpowiedź to format JSON:
```
{
    'fileId': 123,
    'errorMessage': None
}
```

## Plik PlannedResourceSchedule.xsd
Plik 'PlannedResourceSchedule.xsd' znajdujący się w głównym katalogu projektu, służy do weryfikacji danych korzystających z API.

## Wykorzystanie pre-commit w celu walidacji kodu (Niewymagane)
1. Sklonuj repozytorium
2. Utwórz środowisko wirtualne (o ile to możliwe w ramach stacji roboczej)
```
python -m venv path/to/venv
```
3. Zainstaluj pakiety do developmentu
```
python -m pip install -r requirements-dev.txt
```
4. Zainstaluj git hooki pre-commita
```
pre-commit install
```
5. Zainstaluj pakiety potrzebne do działania aplikacji
```
python -m pip install -r requirements.txt
```
