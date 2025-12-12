# Руководство / Usage Guide

[English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

### Installation

```bash
# Clone repository
git clone https://github.com/romashqua/massping.git
cd massping

# Build
rebar3 compile

# Build executable
rebar3 escriptize

# Run tests
rebar3 eunit
```

### macOS Build Instructions

#### Prerequisites

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Erlang and rebar3
brew install erlang rebar3

# Verify installation
erl -version
rebar3 --version
```

#### Building the Binary

```bash
# 1. Clone the repository
git clone https://github.com/romashqua/massping.git
cd massping

# 2. Compile the project
rebar3 compile

# 3. Build escript (portable binary)
rebar3 escriptize

# The binary will be created at:
# _build/default/bin/massping

# 4. (Optional) Copy to project root or PATH
cp _build/default/bin/massping ./massping

# 5. Make executable (if needed)
chmod +x ./massping
```

#### Building a Production Release

```bash
# Build release with embedded Erlang runtime
rebar3 as prod release

# Start the release
_build/prod/rel/massping/bin/massping start

# Or run interactively
_build/prod/rel/massping/bin/massping console

# Stop
_build/prod/rel/massping/bin/massping stop
```

### Basic Usage

### Command Line Options

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
| `--randomize` | Randomize IP scan order | off |
| `--filter-blackhole` | Exclude private/reserved IPs | off |
| `--aggressive` | Fast mode (8K conc, 1.5s, 3 retries) | - |
| `--ultra` | Max speed (15K conc, 800ms, 2 retries) | - |
| `--turbo` | Insane speed for LAN only | - |
| `--stealth` | Stealth mode (500 conc, 5s, randomized) | - |

### Command Line Examples

```bash
# Basic scan (default: 5000 concurrent, 1s timeout)
./massping scan 192.168.1.0/24 -p 80,443,22

# Maximum speed (high concurrency, short timeout)
./massping scan 10.0.0.0/16 -p 80,443 -c 20000 -t 500

# Balanced (medium concurrency with retries for accuracy)
./massping scan 192.168.0.0/16 -p 22,80,443 -c 5000 -t 2000 -r 2

# Conservative (avoid detection)
./massping scan 10.0.0.0/24 -p 80,443 -c 1000 -t 3000 --rate 500

# Export results
./massping scan 192.168.1.0/24 -p 80 -o results.json --format json
./massping scan 192.168.1.0/24 -p 80 -o results.csv --format csv
```

### Erlang API

```erlang
% Start application
application:ensure_all_started(massping).

% Simple scan
{ok, ScanRef} = massping:scan("192.168.1.0/24", [80, 443, 22]).

% Check status
{ok, Status} = massping:status(ScanRef).

% Get results
{ok, Results} = massping:results(ScanRef).

% Advanced scan with options
{ok, ScanRef} = massping:scan(
    "10.0.0.0/16",
    [80, 443],
    #{
        rate_limit => 50000,
        timeout => 2000,
        max_parallel => 100000
    }
).
```

## Distributed Scanning

### Setup Cluster

```bash
# Terminal 1 - Start node 1
./scripts/start_node.sh node1 192.168.1.10

# Terminal 2 - Start node 2
./scripts/start_node.sh node2 192.168.1.11
```

### Run Distributed Scan

```erlang
% Add nodes to cluster
massping_dist:add_node('node2@192.168.1.11').

% Check cluster status
massping_dist:get_cluster_status().

% Run distributed scan
{ok, ScanRef, Results} = massping_dist:scan_cluster(
    ["10.0.0.0/16", "192.168.0.0/16"],
    [80, 443],
    #{
        nodes => ['node1@192.168.1.10', 'node2@192.168.1.11'],
        rate_per_node => 10000,
        distribution_strategy => round_robin
    }
).

% Collect results
{ok, AllResults} = massping_dist:collect_results(ScanRef).
```

## Configuration

Edit `config/massping.config`:

```erlang
[
    {massping, [
        {default_ports, [80, 443, 22, 3389, 8080]},
        {connect_timeout, 1000},
        {rate_limit, 10000},
        {max_parallel, 100000},
        {retry_count, 2},
        {output_format, json}
    ]},
    
    {cluster, [
        {nodes, ['node1@192.168.1.10', 'node2@192.168.1.11']},
        {distribution_strategy, round_robin},
        {rate_per_node, 5000}
    ]}
].
```

## Performance Tuning

### Rate Limiting

```erlang
% Conservative (avoid detection)
massping:scan(CIDR, Ports, #{rate_limit => 1000}).

% Balanced
massping:scan(CIDR, Ports, #{rate_limit => 10000}).

% Aggressive (maximum speed)
massping:scan(CIDR, Ports, #{rate_limit => 100000}).
```

### Timeout Settings

```erlang
% Fast networks
massping:scan(CIDR, Ports, #{timeout => 500}).

% Normal
massping:scan(CIDR, Ports, #{timeout => 1000}).

% Slow networks
massping:scan(CIDR, Ports, #{timeout => 5000}).
```

## Benchmarking

```erlang
% Run all benchmarks
massping_benchmark:run_all().

% Compare with Nmap
massping_benchmark:compare_with_nmap("192.168.1.0/24", [80, 443, 22]).

% Individual benchmarks
massping_benchmark:benchmark_small_network().
massping_benchmark:benchmark_medium_network().
massping_benchmark:benchmark_large_network().
```

## Examples

See `examples/` directory:
- `basic_scan.erl` - Simple scanning examples
- `distributed_scan.erl` - Cluster scanning examples

## Troubleshooting

### Port scanning not working

- Ensure you have network access to target hosts
- Check firewall rules
- Verify rate limits are not too aggressive

### Memory issues with large scans

- Use streaming API for very large ranges
- Reduce `max_parallel` setting
- Split large ranges into smaller chunks

### Cluster nodes not connecting

- Verify network connectivity
- Check Erlang cookie matches on all nodes
- Ensure distributed Erlang is properly configured

## Security Best Practices

1. **Authorization**: Only scan networks you own or have permission to scan
2. **Rate Limiting**: Use conservative rates to avoid detection/blocking
3. **Logging**: All scans are logged for audit purposes
4. **Notifications**: Consider notifying network administrators before large scans

---

<a name="русский"></a>
## Русский

### Сборка на macOS

#### Требования

```bash
# Установка Homebrew (если не установлен)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Установка Erlang и rebar3
brew install erlang rebar3

# Проверка установки
erl -version
rebar3 --version
```

#### Сборка бинарника

```bash
# 1. Клонирование репозитория
git clone https://github.com/romashqua/massping.git
cd massping

# 2. Компиляция проекта
rebar3 compile

# 3. Сборка escript (переносимый бинарник)
rebar3 escriptize

# Бинарник будет создан по пути:
# _build/default/bin/massping

# 4. (Опционально) Копирование в корень проекта
cp _build/default/bin/massping ./massping

# 5. Сделать исполняемым (если нужно)
chmod +x ./massping
```

#### Сборка Production-релиза

Production-релиз включает встроенный Erlang runtime:

```bash
# Сборка релиза со встроенным Erlang
rebar3 as prod release

# Запуск релиза
_build/prod/rel/massping/bin/massping start

# Интерактивный режим
_build/prod/rel/massping/bin/massping console

# Остановка
_build/prod/rel/massping/bin/massping stop
```

### Использование

#### Параметры командной строки

| Параметр | Описание | По умолч. |
|----------|----------|-----------|
| `-p, --ports` | Порты для сканирования (обязат.) | - |
| `-t, --timeout` | Таймаут соединения (мс) | 1000 |
| `-c, --concurrency` | Макс. параллельных соединений | 5000 |
| `-r, --retries` | Кол-во повторов для filtered | 0 |
| `--no-retry` | Отключить повторы | - |
| `--rate` | Лимит запросов/сек | без лимита |
| `-o, --output` | Файл вывода | - |
| `--format` | Формат (json/csv) | json |

#### Примеры команд

```bash
# Базовое сканирование (по умолч.: 5000 параллельных, 1с таймаут)
./massping scan 192.168.1.0/24 -p 80,443,22

# Максимальная скорость (высокий параллелизм, короткий таймаут)
./massping scan 10.0.0.0/16 -p 80,443 -c 20000 -t 500

# Сбалансированный (средний параллелизм с повторами для точности)
./massping scan 192.168.0.0/16 -p 22,80,443 -c 5000 -t 2000 -r 2

# Консервативный (избежать обнаружения)
./massping scan 10.0.0.0/24 -p 80,443 -c 1000 -t 3000 --rate 500

# Экспорт результатов
./massping scan 192.168.1.0/24 -p 80 -o results.json --format json
./massping scan 192.168.1.0/24 -p 80 -o results.csv --format csv
```

#### Параметры (устаревшая таблица — см. выше полную таблицу)

### Режимы сканирования

#### Максимальная скорость
```bash
# Для быстрых сетей (LAN, дата-центры)
./massping scan <CIDR> -p <ports> -c 20000 -t 500
```

#### Сбалансированный режим (рекомендуется)
```bash
# Хороший баланс скорости и точности
./massping scan <CIDR> -p <ports> -c 5000 -t 2000 -r 2
```

#### Консервативный режим
```bash
# Для медленных сетей или избежания обнаружения
./massping scan <CIDR> -p <ports> -c 1000 -t 5000 --rate 500
```

### Устранение неполадок

#### Сканирование не работает

- Проверьте сетевой доступ к целевым хостам
- Проверьте правила файрвола
- Убедитесь, что rate limit не слишком агрессивный

#### Проблемы с памятью

- Используйте streaming API для больших диапазонов
- Уменьшите `max_parallel`
- Разбейте диапазоны на части

#### Узлы кластера не подключаются

- Проверьте сетевую связность
- Убедитесь, что cookie совпадает
- Проверьте настройки distributed Erlang

## Правовое уведомление

⚠️ **ВАЖНО**: Несанкционированное сканирование портов незаконно.

Используйте только для:
- Аудита собственных сетей
- Сетей с письменным разрешением
- Образовательных целей

## Security Best Practices

1. **Authorization**: Only scan networks you own or have permission to scan
2. **Rate Limiting**: Use conservative rates to avoid detection/blocking
3. **Logging**: All scans are logged for audit purposes
4. **Notifications**: Consider notifying network administrators before large scans

## Legal Notice

⚠️ **IMPORTANT**: Unauthorized port scanning is illegal in many jurisdictions.

This tool is intended for:
- Security auditing of your own networks
- Networks where you have explicit written permission
- Educational purposes in controlled lab environments

Always ensure you have proper authorization before scanning any network.
