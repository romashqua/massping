# Architecture / Архитектура

## Overview / Обзор

MassPing построен на принципах Erlang/OTP с иерархическим деревом супервизоров, обеспечивающим отказоустойчивость и высокую доступность.

```
massping_app
    |
    +-- massping_sup (supervisor)
            |
            +-- massping_core (gen_server) - Координация сканирования
            |
            +-- massping_scan_manager (gen_server) - Управление сканами для API
            |
            +-- massping_web (supervisor) - Cowboy HTTP сервер
            |       |
            |       +-- massping_api_handler - REST API endpoints
            |       +-- massping_web_handler - Web UI dashboard
            |       +-- massping_metrics - Prometheus /metrics
            |
            +-- scanner_sup (supervisor)
                    |
                    +-- scanner_worker* (gen_server, dynamic)
```

## Core Components / Основные компоненты

### Scanning Layer / Слой сканирования

#### 1. cidr_parser

**Назначение**: Эффективный парсинг CIDR-диапазонов без нагрузки на память

**Ключевые особенности**:
- Потоковая обработка больших IP-диапазонов
- Нулевая дополнительная память для миллионов IP
- Поддержка CIDR-нотации и IP-диапазонов

**API**:
```erlang
parse/1          % Малые диапазоны - возвращает список
parse_stream/1   % Большие диапазоны - возвращает генератор
count_ips/1      % Подсчёт IP без генерации списка
chunk_range/2    % Разбиение диапазона на чанки
```

#### 2. syn_scan (NIF)

**Назначение**: Высокопроизводительное SYN сканирование на уровне ядра

**Платформы**:
- **Linux**: Raw sockets (AF_INET, SOCK_RAW)
- **macOS**: libpcap для перехвата пакетов

**Преимущества**:
- 3x быстрее TCP connect scan
- Half-open scan (менее заметен)
- Меньше нагрузки на ресурсы

**API**:
```erlang
syn_scan:is_available/0    % Проверка доступности
syn_scan:scan/3            % Сканирование одного порта
syn_scan:scan_batch/4      % Батчевое сканирование
```

#### 3. udp_scanner

**Назначение**: UDP сканирование с сервис-специфичными пробами

**Поддерживаемые сервисы**:
- DNS (порт 53)
- SNMP (порт 161)
- NTP (порт 123)
- TFTP (порт 69)

**API**:
```erlang
udp_scanner:scan/3       % Сканирование одного порта
udp_scanner:scan_batch/2 % Батчевое сканирование
```

#### 4. scanner_worker (gen_server)

**Назначение**: Асинхронное TCP-сканирование портов

**Жизненный цикл**:
1. Получение разрешения от rate limiter
2. Инициация неблокирующего TCP-соединения
3. Ожидание результата с таймаутом
4. Классификация результата (open/closed/filtered)
5. Отправка результата родителю и завершение

**Классификация результатов**:
- `{open, Port}` - Соединение успешно
- `{closed, Port}` - Соединение отклонено
- `{filtered, Port}` - Таймаут или недоступен
- `{error, Reason}` - Другая ошибка

### Service Detection Layer / Слой определения сервисов

#### 5. banner_grabber

**Назначение**: Получение баннеров сервисов для идентификации

**Особенности**:
- Автоматические пробы для разных протоколов
- Парсинг HTTP, SSH, FTP, SMTP заголовков
- Извлечение версий ПО

#### 6. service_detector

**Назначение**: Улучшенное определение сервисов с сигнатурами

**Возможности**:
- 30+ сигнатур сервисов
- Регулярные выражения для версий
- Определение: Apache, nginx, OpenSSH, MySQL, PostgreSQL, Redis, MongoDB и др.

**API**:
```erlang
service_detector:detect/3       % Определение на порту
service_detector:detect_batch/2 % Батчевое определение
```

### Flow Control Layer / Слой управления потоком

#### 7. rate_limiter (gen_server)

**Назначение**: Точный контроль скорости запросов

**Алгоритм**: Token bucket с временным пополнением

**Состояние**:
```erlang
#state{
    rate,           % запросов в секунду
    tokens,         % доступные токены
    max_tokens,     % ёмкость корзины
    last_update,    % временная метка
    strategy,       % uniform | burst
    waiting,        % очередь ожидающих
    stats          % метрики
}
```

#### 8. adaptive_rate (gen_server)

**Назначение**: AIMD-контроль скорости (как TCP congestion)

**Алгоритм**:
- Additive Increase: +N при успехе
- Multiplicative Decrease: /2 при ошибках
- Автоматическая адаптация к сети

### State Management / Управление состоянием

#### 9. scan_state

**Назначение**: Сохранение и восстановление прогресса сканирования

**Возможности**:
- Сохранение в файл (~/.massping_sessions/)
- Сжатие term_to_binary
- Атомарные обновления

**API**:
```erlang
scan_state:save/3          % Сохранить состояние
scan_state:load/1          % Загрузить состояние
scan_state:list_sessions/0 % Список сессий
scan_state:delete/1        % Удалить сессию
```

#### 10. exclude_filter

**Назначение**: Фильтрация IP-адресов для исключения

**Поддерживаемые форматы**:
- Одиночные IP: 192.168.1.1
- CIDR диапазоны: 192.168.0.0/24
- Комментарии: # или //

**API**:
```erlang
exclude_filter:load/1        % Загрузить из файла
exclude_filter:is_excluded/2 % Проверить IP
exclude_filter:filter_targets/2 % Отфильтровать список
```

### API Layer / Слой API

#### 11. massping_web (supervisor)

**Назначение**: HTTP-сервер на Cowboy

**Конфигурация**:
- Порт по умолчанию: 8080
- Статические файлы из priv/

**Роуты**:
```
/           - Web UI dashboard
/api/*      - REST API endpoints
/metrics    - Prometheus metrics
```

#### 12. massping_api_handler

**Назначение**: REST API для управления сканами

**Endpoints**:
```
GET    /api/status              - Статус сервера
GET    /api/scans               - Список активных сканов
POST   /api/scans               - Запустить новый скан
GET    /api/scans/:id           - Статус скана
DELETE /api/scans/:id           - Остановить скан
GET    /api/scans/:id/results   - Результаты скана
GET    /api/sessions            - Сохранённые сессии
POST   /api/sessions/:id/resume - Продолжить сессию
```

#### 13. massping_metrics

**Назначение**: Экспорт метрик в Prometheus формате

**Метрики**:
```
massping_scans_total          - Всего сканов
massping_targets_scanned      - Просканировано целей
massping_ports_open           - Найдено открытых портов
massping_scan_duration_seconds - Длительность сканов
massping_active_connections   - Активных соединений
```

#### 14. massping_web_handler

**Назначение**: Web UI dashboard

**Возможности**:
- Realtime статистика
- Управление кластером
- Запуск/остановка сканов
- Просмотр результатов

### Coordination Layer / Слой координации

#### 15. massping_core (gen_server)

**Назначение**: Оркестрация сканирования и управление состоянием

**Обязанности**:
- Валидация параметров сканирования
- Создание rate limiters
- Chunked parallel scanning
- Сбор и агрегация результатов
- Интеграция с exclude_filter

**Алгоритм Chunked Scanning**:
```
NumChunks = NumSchedulers × 2
ConcurrencyPerChunk = TotalConcurrency / NumChunks
```

#### 16. massping_scan_manager (gen_server)

**Назначение**: Управление сканами для REST API

**Обязанности**:
- Хранение активных сканов в ETS
- Маршрутизация запросов API
- Resume/pause функциональность

#### 17. massping_dist

**Назначение**: Распределённое сканирование в кластере

**Стратегии распределения**:
1. **Round-robin**: Последовательное назначение
2. **Hash-based**: Консистентное хеширование
3. **Least-loaded**: На основе нагрузки узлов

## Поток данных

```
Запрос пользователя
    |
    v
massping:scan/3
    |
    v
massping_core:start_scan/3
    |
    +-- Создание rate_limiter
    |
    +-- Запуск scan_process
            |
            +-- Парсинг CIDR
            |
            +-- Для каждого IP:Port
                    |
                    +-- scanner_sup:start_worker/5
                            |
                            +-- rate_limiter:acquire/1 (блокирующий)
                            |
                            +-- gen_tcp:connect (неблокирующий)
                            |
                            +-- Результат -> Родитель
                                    |
                                    v
                            massping_core (сбор)
                                    |
                                    v
                            Пользователь: massping:results/1
```

## Управление памятью

### Потоковая обработка

Для больших IP-диапазонов (> 10K IP) используется потоковая обработка:

```erlang
Stream = cidr_parser:parse_stream("10.0.0.0/16"),
process_stream(Stream())

process_stream(done) -> ok;
process_stream({IP, NextStream}) ->
    scan_ip(IP),
    process_stream(NextStream()).
```

Это обеспечивает постоянное потребление памяти независимо от размера диапазона.

## Оптимизации производительности

### 1. Параллельная обработка
- Множество одновременных воркеров (настраивается)
- Каждый воркер обрабатывает одну пару IP:Port
- Планировщик Erlang распределяет по ядрам CPU

### 2. Неблокирующий I/O
- Все TCP-операции неблокирующие
- Воркеры не блокируются на сетевом I/O
- Таймауты предотвращают бесконечное ожидание

### 3. Rate Limiting
- Token bucket предотвращает сетевой флуд
- Настраиваемые скорости для узлов кластера
- Адаптивная настройка на основе ошибок

## Отказоустойчивость

### Стратегия супервизии

```
one_for_one: При падении воркера перезапускается только он
simple_one_for_one: Динамический пул с автоматической очисткой
```

### Обработка ошибок

1. **Сетевые ошибки**: Классифицируются, не роняют воркеры
2. **Падения воркеров**: Супервизор перезапускает, сканирование продолжается
3. **Сбой Rate Limiter**: Обнаруживается и перезапускается ядром
4. **Сбой узла** (distributed): Другие узлы продолжают работу

## Масштабируемость

### Вертикальное масштабирование
- Увеличение `max_parallel` воркеров
- Увеличение `rate_limit`
- Эффективнее с большим числом ядер CPU

### Горизонтальное масштабирование
- Добавление узлов в кластер
- Автоматическое распределение работы
- Линейное ускорение с количеством узлов
