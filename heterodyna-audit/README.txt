HETERODYNA SECURITY AUDIT v15.9.4 — SECURITY DASHBOARD: POSTEP I POTWIERDZONE PODATNOSCI

PEŁNA WTYCZKA DO INSTALACJI WORDPRESS
Uaktualnij wp-content/plugins/heterodyna-audit instalując nowe archiwum ZIP.
Zmiana interfejsu: pięć zakładek (Kokpit, Eksplorator, Podatności, Raport, Dziennik),
cztery liczniki i monitor; wstępny podgląd 18 ścieżek podczas skanowania.
Pełne drzewo i dowody po zakończeniu; nazwy plików nie są werdyktami.
Zachowane wszystkie identyfikatory elementów, endpointy AJAX, profile testów,
uprawnienia i sposób zapisu skanu.

HETERODYNA SECURITY AUDIT v15.8.2 — ETAP IX · ZIP 2/2

Pełna aktualizacja wtyczki WordPress. Instalacja: podmień folder wp-content/plugins/heterodyna-audit w odizolowanej instalacji testowej; nie wymagamy danych hostingu.

NOWE: source_proof158 — weryfikuje wszystkie wpisy source_review156 na podstawie aktualnego pliku (SHA-256).
- Rozpoznaje tokeny rzeczywistych operacji echo/print/printf w PHP, bez mylenia ich z komentarzem, napisem czy ?>.
- Jeśli linia zgłoszenia jest niepoprawna, sugeruje poprawną linię wyłącznie przy jednoznacznym dopasowaniu w oknie ±3 linii i tej samej funkcji.
- Wiąże znalezisko z nazwą funkcji, jej zakresem, lokalnymi superglobalnymi wejściami i wywołaniami ochronnymi widocznymi składniowo przed operacją.
- Rozdziela: dowód statyczny tokenu, obserwację funkcji ochronnej, źródło zmienione między modułami tego samego skanu (nie porównanie dwóch historycznych raportów), brak dowodu wykonania oraz potwierdzoną podatność.
- Wszystkie rekordy zawierają hash aktualnego źródła i wyrażenia. Priorytet czterech plików WooCommerce z poprzedniego raportu.
- Panel, drzewo i eksporty HTML/JSON pokazują analizę i ograniczenia.

BEZPIECZEŃSTWO: nowy moduł wykonuje tylko odczyt plików, nie wywołuje HTTP ani handlerów WooCommerce, nie zapisuje danych klienta. Oddzielny istniejący test szkicu WordPress core pozostaje dostępny po zgodzie użytkownika i NIE potwierdza podatności WooCommerce. Nie ma fikcyjnych exploitów.

OGRANICZENIA: nie jest to pełna analiza przepływu danych, symbolic execution ani test przeglądarki. Call-site nonce / capability może być na innej gałęzi; jego obecność nie jest dowodem poprawnego zabezpieczenia. Bez odizolowanej, jednoznacznie powiązanej próby wykonania nie stwierdzamy luki.

SPRAWDZENIE: php tests/source-proof158-test.php; php tests/run-all.php; node --check panel.js.
ETAP IX: 2/2 ZIP ukończony (v15.6.0 + v15.8.2). Dalsza walidacja: kolejny skan na izolowanej instalacji i raport JSON.


PATCH v15.8.2 — selekcja fałszywych alarmów eval():
- Samo T_EVAL nie jest oznaczane jako potwierdzona luka ani „PILNY PRZEGLĄD”.
- Dla wskazanego Engine.php Google Site Kit, weryfikujemy zgodność SHA-256 pliku z udokumentowanym wynikiem testu 2026-10-31 i dokładne linie 1060/1067. Poprawne wewnętrzne użycie nie trafia do findings/kolorów drzewa.
- Dla nieznanych eval() bez wykazanego przepływu HTTP brak alarmu; liczba pozostaje w statystyce diagnostycznej.
- Bezpośrednie eval($_GET/POST/REQUEST/COOKIE[...]) pozostaje żółtym kandydatem wymagającym dowodu. Nie jest automatycznie RCE.
- Wynik testu „42 mod 17 = 8” jest dowodem prawidłowego uruchomienia generatora na stałych danych, NIE dowodem braku wszelkich podatności tej biblioteki.
- Wtyczka nie wykonuje znalezionych eval(); nie modyfikuje Site Kit ani WooCommerce. Stary raport nie jest nadpisywany: rozpocznij nowy skan.


PATCH v15.8.2 — ETAP X, 1/1 ZIP (classification)
- Kolor czerwony wyłącznie przy jawnym rekordzie confirmed_vulnerability + is_exploit_proven + ID i materiale dowodowym; kolor żółty = sygnał, nie luka.
- Skrypty tests/ w samej wtyczce Heterodyna Audit nie generują ustaleń w skanerze; wciąż figurują w drzewie/inwentarzu. Inne komponenty nie są wyłączane tylko za posiadanie folderu tests.
- Oddzielna sekcja classification1582 z licznikami: potwierdzone skutki, statyczne sygnały, kontrola konfiguracji, inventory FILE, wyłączenia testowych fixture'ów.
- Powtarzające się identyfikatory rejestru dowodów są deterministycznie rozróżniane, bez zmiany pierwszego ID.
- Pełna synchronizacja wersji plugin/protokół/JS/testy/eksport.
- Utrzymano aktywne testy w izolowanym WordPressie; nowa klasyfikacja nie dodaje żadnych HTTP ani operacji zapisu.
- UWAGA: żółte wyniki nie zostały uznane za fałszywe; brak wykazania luki nie dowodzi bezpieczeństwa.

15.9.4: pięć zakładek; wstępny podgląd ostatnich 18 indeksowanych plików w trakcie skanu. Nie są prezentowane jako podatności.
