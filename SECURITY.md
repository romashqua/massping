# Security Policy / Политика безопасности

[English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

### Legal Disclaimer

⚠️ **IMPORTANT**: MassPing is a network security tool. Unauthorized port scanning is illegal in many jurisdictions.

**You may only use this tool on:**
- Networks you own
- Networks where you have explicit written permission
- Controlled lab environments for educational purposes

**We are not responsible for:**
- Illegal use of this software
- Damage caused by misuse
- Legal consequences of unauthorized scanning

### Responsible Use Guidelines

1. **Always obtain permission** before scanning any network
2. **Document authorization** in writing when possible
3. **Use conservative rate limits** to avoid disruption
4. **Notify network administrators** before large-scale scans
5. **Respect robots.txt and network policies**

### Security Considerations

When using MassPing:

1. **Rate Limiting**: Use conservative rates (1000-5000 req/sec) to avoid:
   - Network disruption
   - Detection by IDS/IPS systems
   - IP blocking

2. **Logging**: All scans are logged. Review logs for:
   - Audit compliance
   - Troubleshooting
   - Evidence if questions arise

3. **Network Isolation**: Consider scanning from:
   - Dedicated security testing network
   - Isolated VMs
   - Approved security testing infrastructure

### Reporting Security Vulnerabilities

If you discover a security vulnerability in MassPing:

1. **Do not** open a public GitHub issue
2. Email the maintainers privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

---

<a name="русский"></a>
## Русский

### Правовой отказ

⚠️ **ВАЖНО**: MassPing — инструмент сетевой безопасности. Несанкционированное сканирование портов незаконно во многих юрисдикциях.

**Вы можете использовать этот инструмент только на:**
- Сетях, которыми вы владеете
- Сетях, где у вас есть явное письменное разрешение
- Контролируемых лабораторных средах в образовательных целях

**Мы не несём ответственности за:**
- Незаконное использование этого ПО
- Ущерб от неправильного использования
- Правовые последствия несанкционированного сканирования

### Правила ответственного использования

1. **Всегда получайте разрешение** перед сканированием любой сети
2. **Документируйте авторизацию** письменно когда возможно
3. **Используйте консервативные rate limits** чтобы избежать сбоев
4. **Уведомляйте администраторов** перед масштабными сканированиями
5. **Соблюдайте политики сети**

### Соображения безопасности

При использовании MassPing:

1. **Rate Limiting**: Используйте консервативные скорости (1000-5000 запросов/сек):
   - Избежание сбоев сети
   - Обход обнаружения IDS/IPS
   - Предотвращение блокировки IP

2. **Логирование**: Все сканирования логируются. Проверяйте логи для:
   - Соответствия аудиту
   - Устранения неполадок
   - Доказательств при возникновении вопросов

3. **Сетевая изоляция**: Рассмотрите сканирование из:
   - Выделенной сети тестирования безопасности
   - Изолированных VM
   - Одобренной инфраструктуры тестирования

### Сообщение об уязвимостях

Если вы обнаружили уязвимость в MassPing:

1. **Не** открывайте публичный GitHub issue
2. Напишите мейнтейнерам приватно
3. Включите:
   - Описание уязвимости
   - Шаги воспроизведения
   - Потенциальное влияние
   - Предлагаемое исправление (если есть)

Мы ответим в течение 48 часов и будем работать с вами над решением проблемы.

---

## Supported Versions / Поддерживаемые версии

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Contact / Контакты

- GitHub: https://github.com/romashqua/massping
- Issues: https://github.com/romashqua/massping/issues
