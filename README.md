# MassPing

[English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

High-performance distributed port scanner written in Erlang/OTP.

### Features

- **High Performance**: 100K+ concurrent connections with chunked parallel scanning
- **SYN Scan**: Native NIF-based SYN scanning (3x faster, requires root)
- **Distributed**: Linear scaling across cluster nodes
- **Memory Efficient**: < 5KB per process
- **Web UI**: Browser-based dashboard for cluster management
- **REST API**: Full HTTP API for automation
- **UDP Scanning**: DNS, SNMP, NTP service discovery
- **Service Detection**: Enhanced banner grabbing with 30+ signatures
- **Session Resume**: Save and resume interrupted scans
- **Multiple Output Formats**: JSON, CSV, XML (nmap-style), Grepable
- **Prometheus Metrics**: /metrics endpoint for monitoring
- **Exclude Files**: Skip IP ranges from scanning
- **IP Randomization**: Evade IDS/IPS detection with random scan order
- **Blackhole Filter**: Auto-exclude private/reserved IP ranges
- **Adaptive Rate Control**: AIMD-based automatic rate adjustment
- **Fault Tolerant**: Automatic recovery from failures
- **Stream Processing**: Handle millions of IPs without loading into memory

### Performance Targets

- Scan /16 network (65,536 hosts × 3 ports) in < 30 seconds
- Support 500K+ concurrent TCP connections
- Distribute load across 10+ physical servers

### Quick Start

#### Prerequisites

- Erlang/OTP 25+ installed
- rebar3 build tool

#### Installation on macOS

```bash
# Install Erlang via Homebrew
brew install erlang rebar3

# Clone and build
git clone https://github.com/romashqua/massping.git
cd massping
rebar3 compile
rebar3 escriptize
```

#### Build Binary (escript)

```bash
# Compile project
rebar3 compile

# Create executable binary
rebar3 escriptize

# Binary will be at: _build/default/bin/massping
# Or copy to project root:
cp _build/default/bin/massping ./massping
```

#### Build Release (Production)

```bash
# Build production release with embedded Erlang runtime
rebar3 as prod release

# Release will be at: _build/prod/rel/massping/
# Start with:
_build/prod/rel/massping/bin/massping start
```

### Basic Usage

#### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports` | Ports to scan (required) | - |
| `-t, --timeout` | Connection timeout (ms) | 1000 |
| `-c, --concurrency` | Max concurrent connections | 5000 |
| `-r, --retries` | Retry count for filtered | 0 |
| `--rate` | Rate limit (requests/sec) | unlimited |
| `-o, --output` | Output file | - |
| `--format` | Output format (json/csv/xml/grepable) | json |
| `--syn` | SYN scan (requires root/sudo) | auto |
| `--no-syn` | Force TCP connect scan | - |
| `--udp` | UDP scan mode | off |
| `--grab-banner` | Grab service banners | off |
| `--detect-service` | Enhanced service detection | off |
| `--exclude-file` | File with IPs/CIDRs to exclude | - |
| `--exclude` | Inline exclude (can repeat) | - |
| `--session` | Save progress to session ID | - |
| `--resume` | Resume from saved session | - |
| `--list-sessions` | List saved sessions | - |
| `--web` | Start web UI server | off |
| `--web-port` | Web server port | 8080 |
| `--randomize` | Randomize IP scan order | off |
| `--filter-blackhole` | Exclude private/reserved IPs | off |
| `--batch-size` | Batch size for SYN scan | 1000 |
| `--chunks` | Chunk multiplier (x CPUs) | 2 |
| `--aggressive` | Fast mode (50K conc, 500ms, 1 retry) | - |
| `--ultra` | Balanced speed (20K conc, 800ms, 2 retries) | - |
| `--turbo` | LAN speed (50K conc, 300ms, batch 5K) | - |
| `--stealth` | Stealth mode (500 conc, 5s, randomized) | - |

```bash
# Basic scan (default: 5000 concurrent, 1s timeout)
./massping scan 192.168.1.0/24 -p 80,443,22

# SYN scan (requires sudo, 3x faster)
sudo ./massping scan 10.0.0.0/16 -p 80,443 --syn --aggressive

# UDP scan for DNS, SNMP, NTP
./massping scan 192.168.0.0/16 -p 53,161,123 --udp

# With service detection
./massping scan 192.168.1.0/24 -p 22,80,443 --detect-service -o services.json

# Using exclude file
./massping scan 10.0.0.0/8 -p 80 --exclude-file excludes.txt

# Save session for resume
./massping scan 10.0.0.0/8 -p 80 --session my-scan

# Resume interrupted scan
./massping resume my-scan

# Start web UI
./massping --web --web-port 8888

# Export to different formats
./massping scan 10.0.0.0/24 -p 80 --format xml -o scan.xml
./massping scan 10.0.0.0/24 -p 80 --format grepable -o scan.grep
```

### Erlang Shell Usage

```erlang
% Start application
application:start(massping).

% Simple scan
massping:scan("192.168.1.0/24", [80, 443, 22]).

% Advanced scan with options
massping:scan("10.0.0.0/16", [80, 443], #{
    rate_limit => 50000,
    timeout => 2000,
    max_parallel => 100000
}).

% Distributed scan
massping_dist:scan_cluster(
    ["10.0.0.0/16", "192.168.0.0/16"],
    [80, 443],
    #{nodes => ['node1@host', 'node2@host'],
      rate_per_node => 5000}
).
```

### Benchmarks

Comparison with Nmap (65,536 hosts, 3 ports):

| Tool | Time | Speed |
|------|------|-------|
| Nmap (1 thread) | ~300 sec | ~650 targets/sec |
| Nmap (-T5, 100 threads) | ~60 sec | ~3,200 targets/sec |
| MassPing (1 node) | ~15 sec | ~13,000 targets/sec |
| MassPing (5 nodes) | ~3 sec | ~65,000 targets/sec |

---

<a name="русский"></a>
## Русский

Высокопроизводительный распределённый сканер портов на Erlang/OTP.

### Возможности

- **Высокая производительность**: 100K+ одновременных соединений с чанковым параллелизмом
- **SYN Scan**: Нативный NIF-based SYN сканер (3x быстрее, требует root)
- **Распределённость**: Линейное масштабирование в кластере
- **Эффективность памяти**: < 5KB на процесс
- **Web UI**: Браузерный дашборд для управления кластером
- **REST API**: Полное HTTP API для автоматизации
- **UDP сканирование**: Обнаружение DNS, SNMP, NTP сервисов
- **Определение сервисов**: Улучшенный banner grabbing с 30+ сигнатурами
- **Возобновление сессий**: Сохранение и продолжение прерванных сканов
- **Форматы вывода**: JSON, CSV, XML (nmap-style), Grepable
- **Prometheus метрики**: /metrics endpoint для мониторинга
- **Файлы исключений**: Пропуск IP диапазонов при сканировании
- **Рандомизация IP**: Обход IDS/IPS за счёт случайного порядка сканирования
- **Фильтр Blackhole**: Автоисключение приватных/зарезервированных диапазонов
- **Адаптивный Rate Control**: Автоматическая подстройка скорости (AIMD)
- **Отказоустойчивость**: Автоматическое восстановление при сбоях
- **Потоковая обработка**: Миллионы IP без загрузки в память

### Целевые показатели

- Сканирование /16 сети (65 536 хостов × 3 порта) за < 30 секунд
- Поддержка 500K+ одновременных TCP-соединений
- Распределение нагрузки на 10+ физических серверов

### Быстрый старт

#### Требования

- Erlang/OTP 25+ установлен
- Сборщик rebar3

#### Установка на macOS

```bash
# Установка Erlang через Homebrew
brew install erlang rebar3

# Клонирование и сборка
git clone https://github.com/romashqua/massping.git
cd massping
rebar3 compile
rebar3 escriptize
```

#### Сборка бинарника (escript)

```bash
# Компиляция проекта
rebar3 compile

# Создание исполняемого бинарника
rebar3 escriptize

# Бинарник будет в: _build/default/bin/massping
# Скопировать в корень проекта:
cp _build/default/bin/massping ./massping
```

#### Сборка релиза (Production)

```bash
# Сборка production-релиза со встроенным Erlang runtime
rebar3 as prod release

# Релиз будет в: _build/prod/rel/massping/
# Запуск:
_build/prod/rel/massping/bin/massping start
```

### Использование

#### Параметры командной строки

| Параметр | Описание | По умолч. |
|----------|----------|-----------|
| `-p, --ports` | Порты для сканирования (обязат.) | - |
| `-t, --timeout` | Таймаут соединения (мс) | 1000 |
| `-c, --concurrency` | Макс. параллельных соединений | 5000 |
| `-r, --retries` | Кол-во повторов для filtered | 0 |
| `--rate` | Лимит запросов/сек | без лимита |
| `-o, --output` | Файл вывода | - |
| `--format` | Формат (json/csv/xml/grepable) | json |
| `--syn` | SYN сканирование (требует root/sudo) | авто |
| `--no-syn` | Принудительно TCP connect | - |
| `--udp` | UDP сканирование | выкл |
| `--grab-banner` | Получить баннеры сервисов | выкл |
| `--detect-service` | Улучшенное определение сервисов | выкл |
| `--exclude-file` | Файл с IP/CIDR для исключения | - |
| `--exclude` | Inline исключение (можно повторять) | - |
| `--session` | Сохранить прогресс в сессию | - |
| `--resume` | Продолжить сохранённую сессию | - |
| `--list-sessions` | Показать сохранённые сессии | - |
| `--web` | Запустить web UI сервер | выкл |
| `--web-port` | Порт web сервера | 8080 |
| `--randomize` | Случайный порядок IP | выкл |
| `--filter-blackhole` | Исключить приватные IP | выкл |
| `--batch-size` | Размер батча для SYN | 1000 |
| `--chunks` | Множитель чанков (x CPUs) | 2 |
| `--aggressive` | Быстрый (50K conc, 500ms, 1 retry) | - |
| `--ultra` | Баланс скорость/точность (20K, 800ms) | - |
| `--turbo` | LAN скорость (50K, 300ms, batch 5K) | - |
| `--stealth` | Скрытный режим (500 conc, 5s) | - |

#### Примеры команд

```bash
# Базовое сканирование
./massping scan 192.168.1.0/24 -p 80,443,22

# SYN сканирование (требует sudo, 3x быстрее)
sudo ./massping scan 10.0.0.0/16 -p 80,443 --syn --aggressive

# UDP сканирование для DNS, SNMP, NTP
./massping scan 192.168.0.0/16 -p 53,161,123 --udp

# С определением сервисов
./massping scan 192.168.1.0/24 -p 22,80,443 --detect-service -o services.json

# С файлом исключений
./massping scan 10.0.0.0/8 -p 80 --exclude-file excludes.txt

# Сохранение сессии для продолжения
./massping scan 10.0.0.0/8 -p 80 --session my-scan

# Продолжение прерванного сканирования
./massping resume my-scan

# Запуск web UI
./massping --web --web-port 8888

# Экспорт в разные форматы
./massping scan 10.0.0.0/24 -p 80 --format xml -o scan.xml
./massping scan 10.0.0.0/24 -p 80 --format grepable -o scan.grep
```

#### Erlang Shell

```erlang
% Запуск приложения
application:start(massping).

% Простое сканирование
massping:scan("192.168.1.0/24", [80, 443, 22]).

% Сканирование с параметрами
massping:scan("10.0.0.0/16", [80, 443], #{
    rate_limit => 50000,    % запросов/сек
    timeout => 2000,        % таймаут в мс
    max_parallel => 100000  % макс. параллельных соединений
}).

% Получение статуса
{ok, Status} = massping:status(ScanRef).

% Получение результатов
{ok, Results} = massping:results(ScanRef).
```

### Распределённое сканирование

#### Настройка кластера

```bash
# Терминал 1 - Узел 1 (координатор)
erl -sname node1 -setcookie massping_secret -pa _build/default/lib/*/ebin

# Терминал 2 - Узел 2
erl -sname node2 -setcookie massping_secret -pa _build/default/lib/*/ebin
```

#### Запуск распределённого сканирования

```erlang
%% На узле-координаторе:

%% 1. Запуск приложения
application:ensure_all_started(massping).

%% 2. Подключение узлов
net_adm:ping('node2@hostname').
massping_dist:add_node('node2@hostname').

%% 3. Проверка кластера
massping_dist:get_cluster_status().

%% 4. Запуск распределённого сканирования
{ok, ScanRef, Results} = massping_dist:scan_cluster(
    ["10.0.0.0/16", "192.168.0.0/16"],
    [80, 443],
    #{
        nodes => ['node1@192.168.1.10', 'node2@192.168.1.11'],
        rate_per_node => 10000,
        distribution_strategy => round_robin  % или hash_based, least_loaded
    }
).

%% 5. Сбор результатов
{ok, AllResults} = massping_dist:collect_results(ScanRef).
```

#### Стратегии распределения

| Стратегия | Описание |
|-----------|----------|
| `round_robin` | Равномерно по узлам |
| `hash_based` | По хэшу IP (консистентность) |
| `least_loaded` | На наименее загруженный |

### Архитектура

#### Chunked Parallel Scanning

MassPing автоматически разбивает targets на чанки по количеству CPU scheduler'ов:

```
NumChunks = NumSchedulers × 2
ConcurrencyPerChunk = TotalConcurrency / NumChunks

Пример для M3 Max (12 cores):
- 24 параллельных чанка
- При -c 24000 → 1000 соединений на чанк
- Каждый чанк привязан к своему scheduler'у
```

#### Основные модули

| Модуль | Описание |
|--------|----------|
| `cidr_parser` | Потоковый парсер CIDR в IP-адреса |
| `scan_randomizer` | Рандомизация порядка IP, blackhole фильтр |
| `banner_grabber` | Получение и парсинг баннеров сервисов |
| `adaptive_rate` | AIMD-контроль скорости (как TCP congestion) |
| `rate_limiter` | Точный контроль скорости (gen_server) |
| `scanner_worker` | Неблокирующий TCP-сканер (gen_server) |
| `scanner_sup` | Динамический супервизор воркеров |
| `massping_core` | Координация сканирования с чанками |
| `massping_dist` | Распределённые операции |
| `massping` | CLI и публичный API |

### Конфигурация

Файл `config/massping.config`:

```erlang
[
    {massping, [
        {default_ports, [80, 443, 22, 3389, 8080]},
        {connect_timeout, 1000},    % таймаут соединения, мс
        {rate_limit, 10000},        % запросов/сек
        {max_parallel, 100000},     % макс. параллельных соединений
        {retry_count, 2},           % количество повторов
        {output_format, json}       % формат вывода
    ]},
    
    {cluster, [
        {nodes, ['node1@192.168.1.10', 'node2@192.168.1.11']},
        {distribution_strategy, round_robin}
    ]}
].
```

### Бенчмарки

Сравнение с Nmap (65 536 хостов, 3 порта):

| Инструмент | Время | Скорость |
|------------|-------|----------|
| Nmap (1 поток) | ~300 сек | ~650 целей/сек |
| Nmap (-T5, 100 потоков) | ~60 сек | ~3 200 целей/сек |
| MassPing (1 узел) | ~15 сек | ~13 000 целей/сек |
| MassPing (5 узлов) | ~3 сек | ~65 000 целей/сек |

### Разработка

```bash
# Запуск тестов
rebar3 eunit

# Запуск бенчмарков
rebar3 shell
> massping_benchmark:run_all().

# Режим разработки
rebar3 shell
```

---

## Legal Notice / Правовое уведомление

⚠️ **WARNING / ПРЕДУПРЕЖДЕНИЕ**: 

**EN**: Unauthorized port scanning is illegal in many jurisdictions. This tool is intended for security auditing of your own networks or networks where you have explicit written permission. Always ensure you have proper authorization before scanning.

**RU**: Несанкционированное сканирование портов является незаконным во многих юрисдикциях. Этот инструмент предназначен для аудита безопасности собственных сетей или сетей, на сканирование которых получено письменное разрешение. Всегда убеждайтесь в наличии надлежащего разрешения перед сканированием.

## License / Лицензия

Apache License 2.0 - см. файл [LICENSE](LICENSE)

## Contributing / Участие в разработке

**EN**: Contributions are welcome! Please ensure all tests pass before submitting PRs. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**RU**: Мы рады вашему участию! Пожалуйста, убедитесь, что все тесты проходят перед отправкой PR. См. [CONTRIBUTING.md](CONTRIBUTING.md) для руководства.

## Author / Автор

romashqua

## Links / Ссылки

- [Documentation / Документация](docs/)
- [Architecture / Архитектура](docs/ARCHITECTURE.md)
- [Usage Guide / Руководство](docs/USAGE.md)
- [Issues / Баги](https://github.com/romashqua/massping/issues)
