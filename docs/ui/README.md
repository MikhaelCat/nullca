# 🖥️ NullCA Interactive Terminal Cockpit ("Wireshark + Burp for CLI")

<div align="center">

```
  ███▄    █  █    ██  ██▓     ██▓     ▄████▄   ▄▄▄      
  ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██▀ ▀█  ▒████▄    
 ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ▒▓█    ▄ ▒██  ▀█▄  
 ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░    ▒▓▓▄ ▄██▒░██▄▄▄▄██ 
 ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒ ▓███▀ ░ ▓█   ▓██▒
```

**High-Performance Terminal Wire Inspector, Interactive Request Repeater, Side-by-Side Diff & Secret Harvester**

</div>

---

## 📌 Обзор

**NullCA Cockpit** — это интерактивный терминальный интерфейс (TUI) нового поколения, разработанный на базе **Ratatui** и **Crossterm**. Он объединяет аналитическую мощь **Wireshark** и практическое удобство **Burp Suite Repeater**, работая прямо в консоли Linux через eBPF uprobes.

Интерфейс не требует веб-браузеров, X11 или тяжёлых GUI-фреймворков и полноценно функционирует по SSH, в tmux-сессиях, в защищённых анклавах и на соревновательных полигонах CTF Attack-Defense.

---

## 🗂️ Документация раздела `docs/ui/`

| Документ | Описание |
| :--- | :--- |
| **[KEYBOARD_AND_SHORTCUTS.md](KEYBOARD_AND_SHORTCUTS.md)** | Полный справочник горячих клавиш, навигации и жестов мыши |
| **[REPEATER_AND_TAMPER.md](REPEATER_AND_TAMPER.md)** | Руководство по встроенному Request Repeater & Tamper Cockpit (`[R]`) |
| **[INSPECTOR_TABS.md](INSPECTOR_TABS.md)** | 7 специализированных вкладок инспектора (Headers, Protobuf, Secrets, cURL, WS, X.509, Diff) |
| **[FILTER_DSL_GUIDE.md](FILTER_DSL_GUIDE.md)** | Руководство по языку живой фильтрации трафика Filter DSL |

---

## 📐 Архитектура экрана Cockpit

Терминал разделён на адаптивные сплит-панели с динамической подсветкой активного фокуса:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ⚡ NullCA Cockpit v0.2.0 [LIVE] [BASE: #3]    Packets: 1,420 | Filtered: 42 | 120 KB/s  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Active Filter DSL: proto == "http1" && status >= 400 (Press '/' to edit, '?' for help) │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ #  │ DIR │ PROTO │ PROCESS │ PID  │ SIZE  │ SECURITY │ PAYLOAD PREVIEW                 │
│────┼─────┼───────┼─────────┼──────┼───────┼──────────┼─────────────────────────────────│
│ 1  │ OUT │ HTTP1 │ curl    │ 4120 │ 340 B │ [FLAG]   │ POST /api/v1/auth HTTP/1.1      │
│ 2  │ IN  │ HTTP1 │ curl    │ 4120 │ 128 B │ -        │ HTTP/1.1 200 OK                 │
│ 3📌│ OUT │ WS    │ app     │ 5501 │ 84 B  │ [JWT]    │ [TEXT] {"action":"ping"}        │
│ 4  │ IN  │ WS    │ app     │ 5501 │ 92 B  │ -        │ [TEXT] {"status":"pong"}        │
├──────────────────────────────────────────────────────┬─────────────────────────────────┤
│ [1] Info  [2] Protobuf  [3] Secrets  [4] cURL  [5] WS│ Raw Hex & ASCII Dump            │
│ [6] X.509  [7] Diff                                  │                                 │
│──────────────────────────────────────────────────────│ 00000000: 50 4f 53 54 20...     │
│ Process: curl (PID: 4120)  FD: 3  Direction: Egress  │ 00000010: 48 6f 73 74 3a...     │
│ Protocol: Http1  Payload Size: 340 bytes             │                                 │
│                                                      │ ▲                               │
│ --- HTTP/1.1 Header Dissection ---                   │ █ [Scrollbar: 30%]              │
│ Request: POST /api/v1/auth HTTP/1.1                  │ ▼                               │
│   Host: target.internal:8443                         │                                 │
│   Authorization: Bearer eyJhbGciOi... [JWT]          │                                 │
│   Content-Type: application/json                     │                                 │
│                                                      │                                 │
│ --- Body (32 bytes) ---                              │                                 │
│ {"user":"admin","flag":"FLAG{...}"}                  │                                 │
├──────────────────────────────────────────────────────┴─────────────────────────────────┤
│ [q] Quit  [Space] Pause  [/] Filter  [R] Repeater  [r] FastReplay  [f] Fullscreen  [s] Export │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Запуск TUI Cockpit

### 1. Трассировка запущенного процесса по имени или PID:
```bash
sudo nullca trace --name nginx --ui
sudo nullca trace --pid 1337 --ui
```

### 2. Запуск утилиты или сервиса с немедленной трассировкой (Spawn & Trace):
```bash
sudo nullca run --ui -- curl -s https://api.github.com/user
sudo nullca run --ui -- ./my_microservice
```

### 3. Запуск в режиме эмуляции (демо-трафик для отладки):
```bash
nullca trace --emulate --ui
```

### 4. Подключение к фоновому демону NullCA через UNIX сокет:
```bash
nullca stream --socket /tmp/nullca.sock
```

---

## 🌟 Ключевые возможности Cockpit v2.0

1. **Встроенный Request Repeater & Tamper (`[R]`)**:
   - Полный аналог Burp Repeater прямо в терминале.
   - Позволяет изменять метод, хост, порт, путь, заголовки и тело любого перехваченного запроса.
   - Отправка запроса по `[Ctrl+R]` с мгновенным замером **TTFB** и латентности.
2. **Side-by-Side & Unified Diff Engine (`[d]`)**:
   - Фиксация базового пакета 📌 и построчное сравнение заголовков и тел любых двух запросов.
3. **Плавный скроллинг во всех окнах**:
   - Клавиши `j/k`, `PgUp/PgDn`, `Home/End` и колесо мыши прокручивают длинные JSON/Protobuf/Hex структуры без обрезания.
   - Нативные полосы прокрутки Ratatui `Scrollbar`.
4. **Полноэкранный режим панелей (`[f]` / `[m]`)**:
   - Мгновенное переключение активного окна на 100% высоты терминала.
5. **Интерактивное меню экспорта (`[s]`)**:
   - Сохранение сырого тела пакета (`.bin`), готового `.sh` скрипта cURL, дампа PCAP-NG, HAR 1.2 или схемы OpenAPI 3.0.
6. **Контекстная справка (`[?]` / `[h]`)**:
   - Быстрый доступ к шпаргалке по горячим клавишам, синтаксису Filter DSL и бейджам безопасности.
