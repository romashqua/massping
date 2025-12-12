# Contributing / Участие в разработке

[English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

We love your input! We want to make contributing to MassPing as easy and transparent as possible.

### Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code follows the existing style
6. Issue that pull request!

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/massping.git
cd massping

# Add upstream remote
git remote add upstream https://github.com/romashqua/massping.git

# Create a branch for your feature
git checkout -b feature/your-feature-name

# Install dependencies and build
rebar3 compile

# Run tests
rebar3 eunit
```

### Code Style

- Follow standard Erlang coding conventions
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions small and focused
- Use type specs where appropriate

```erlang
%% Good example
-spec scan_port(ip_address(), port_number(), timeout()) -> scan_result().
scan_port(IP, Port, Timeout) ->
    case gen_tcp:connect(IP, Port, [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            gen_tcp:close(Socket),
            {open, Port};
        {error, econnrefused} ->
            {closed, Port};
        {error, _} ->
            {filtered, Port}
    end.
```

### Commit Messages

Use clear and meaningful commit messages:

```
feat: add SYN scanning support
fix: resolve memory leak in rate limiter
docs: update Russian documentation
test: add integration tests for distributed scanning
refactor: simplify CIDR parser logic
```

Format:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation changes
- `test:` adding tests
- `refactor:` code refactoring
- `perf:` performance improvements
- `chore:` maintenance tasks

### Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the documentation in `docs/` if needed
3. The PR will be merged once you have approval from maintainers

### Testing

Before submitting a PR, make sure:

```bash
# All tests pass
rebar3 eunit

# No compilation warnings
rebar3 compile

# Code style is correct
# (manual review for now)
```

### Reporting Bugs

Use GitHub Issues with the following information:

- **Description**: Clear description of the bug
- **Steps to Reproduce**: How to reproduce the issue
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Erlang version, MassPing version

### Feature Requests

We welcome feature requests! Please include:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Any alternative solutions considered?

### License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

<a name="русский"></a>
## Русский

Мы рады вашему участию! Мы хотим сделать вклад в MassPing максимально простым и прозрачным.

### Процесс разработки

Мы используем GitHub для хостинга кода, отслеживания issues и feature requests, а также принятия pull requests.

1. Сделайте форк репозитория и создайте ветку от `main`
2. Если добавили код, добавьте тесты
3. Если изменили API, обновите документацию
4. Убедитесь, что тесты проходят
5. Следуйте существующему стилю кода
6. Отправьте pull request!

### Начало работы

```bash
# Клонирование вашего форка
git clone https://github.com/YOUR_USERNAME/massping.git
cd massping

# Добавление upstream remote
git remote add upstream https://github.com/romashqua/massping.git

# Создание ветки для фичи
git checkout -b feature/your-feature-name

# Установка зависимостей и сборка
rebar3 compile

# Запуск тестов
rebar3 eunit
```

### Стиль кода

- Следуйте стандартным конвенциям Erlang
- Используйте понятные имена переменных и функций
- Добавляйте комментарии для сложной логики
- Делайте функции маленькими и сфокусированными
- Используйте type specs где уместно

### Сообщения коммитов

Используйте понятные сообщения коммитов:

```
feat: добавлена поддержка SYN-сканирования
fix: исправлена утечка памяти в rate limiter
docs: обновлена русская документация
test: добавлены интеграционные тесты
refactor: упрощена логика CIDR парсера
```

### Процесс Pull Request

1. Обновите README.md с деталями изменений, если применимо
2. Обновите документацию в `docs/` если нужно
3. PR будет смержен после одобрения мейнтейнерами

### Тестирование

Перед отправкой PR убедитесь:

```bash
# Все тесты проходят
rebar3 eunit

# Нет предупреждений компиляции
rebar3 compile
```

### Сообщения об ошибках

Используйте GitHub Issues с информацией:

- **Описание**: Чёткое описание бага
- **Шаги воспроизведения**: Как воспроизвести проблему
- **Ожидаемое поведение**: Что должно происходить
- **Фактическое поведение**: Что происходит на самом деле
- **Окружение**: ОС, версия Erlang, версия MassPing

### Запросы на новые функции

Мы приветствуем запросы на функции! Пожалуйста, укажите:

- **Сценарий использования**: Зачем нужна эта функция?
- **Предлагаемое решение**: Как это должно работать?
- **Альтернативы**: Рассмотренные альтернативные решения?

### Лицензия

Участвуя в разработке, вы соглашаетесь, что ваши вклады будут лицензированы под Apache License 2.0.

---

## Contact / Контакты

- GitHub Issues: https://github.com/romashqua/massping/issues
- Author / Автор: romashqua
