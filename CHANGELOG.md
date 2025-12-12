# Changelog / История изменений

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-12

### Added / Добавлено
- Initial release / Первый релиз
- TCP CONNECT port scanning / TCP CONNECT сканирование портов
- CIDR notation support / Поддержка CIDR нотации
- Stream processing for large IP ranges / Потоковая обработка больших диапазонов
- Rate limiting with token bucket algorithm / Rate limiting с алгоритмом token bucket
- Distributed scanning across Erlang cluster / Распределённое сканирование в кластере
- CLI interface with escript / CLI интерфейс с escript
- JSON/CSV export / Экспорт в JSON/CSV
- Benchmark module / Модуль бенчмарков
- Comprehensive documentation / Полная документация

### Distribution Strategies / Стратегии распределения
- Round-robin distribution
- Hash-based distribution
- Least-loaded distribution

### Performance / Производительность
- Support for 100K+ concurrent connections
- Memory efficient: < 5KB per process
- Linear scaling with cluster nodes

## [Unreleased] / В разработке

### Planned / Планируется
- SYN scanning via NIF / SYN сканирование через NIF
- UDP port scanning / UDP сканирование
- Service detection / Определение сервисов
- Banner grabbing / Получение баннеров
- Web UI dashboard / Веб-интерфейс
- Prometheus metrics / Метрики Prometheus
- Result persistence (PostgreSQL/SQLite) / Сохранение результатов
