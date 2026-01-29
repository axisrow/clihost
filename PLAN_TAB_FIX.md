# План: Радикальное исправление клавиши Tab в TTYD терминале

**Выбранная стратегия**: Последовательно попробовать два подхода

## Проблема

Клавиша Tab не работает для автодополнения bash в веб-терминале TTYD — вместо этого вставляются пробелы или фокус переключается на другие элементы страницы.

### История неудачных попыток (коммиты b35a11a → 29134e3)
1. `dispatchEvent()` на `.xterm-helper-textarea` — xterm.js игнорирует синтетические события
2. `term.input('\t')` — не проходит через WebSocket к серверу

### Корневая причина
- xterm.js проверяет `event.isTrusted` и игнорирует синтетические KeyboardEvent
- `term.input()` триггерит `onData`, но TTYD использует собственный обработчик `onTerminalData` с префиксом протокола
- Iframe boundary усложняет доступ к внутренним API TTYD

## Выбранный подход: Инъекция скрипта в TTYD iframe + правильный API

Комбинация двух техник:
1. **Родительская страница**: Блокировать браузерную навигацию по Tab, когда фокус в терминале
2. **Внутри iframe**: Использовать `window.term` и WebSocket напрямую для отправки Tab

## Изменения

### Файл: `/Users/axisrow/Projects/clihost/app/ttyd_proxy.py`

#### 1. Изменить `tab_handler_script` (строки 518-562)

**Новый подход для родительской страницы:**
```javascript
<script>
(function() {
  var iframe = document.getElementById('terminal');

  // Блокируем Tab на уровне родительской страницы
  // чтобы браузер не переключал фокус между элементами
  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Tab') return;

    // Если фокус в iframe или на iframe - блокируем браузерную навигацию
    if (document.activeElement === iframe ||
        iframe.contains(document.activeElement)) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);

  // Устанавливаем фокус на iframe при клике
  iframe.addEventListener('focus', function() {
    try {
      iframe.contentWindow.focus();
    } catch(e) {}
  });
})();
</script>
```

#### 2. Модифицировать `proxy_ttyd_http()` (строки 822-861)

Добавить инъекцию скрипта в HTML-ответы от TTYD:

```python
def proxy_ttyd_http(self, upstream_path, port):
    """Proxy HTTP request to TTYD process."""
    # ... существующий код ...

    data = resp.read()
    content_type = ''
    for key, value in resp.getheaders():
        if key.lower() == 'content-type':
            content_type = value
            break

    # Инъекция скрипта для исправления Tab в HTML-ответах
    if 'text/html' in content_type and data:
        data = self.inject_tab_fix_script(data)

    # ... остальной код ...
```

#### 3. Добавить новый метод `inject_tab_fix_script()`

```python
TAB_FIX_SCRIPT = b'''
<script>
(function() {
  // Ждём загрузки терминала
  function waitForTerm(cb) {
    if (window.term) { cb(window.term); return; }
    var i = setInterval(function() {
      if (window.term) { clearInterval(i); cb(window.term); }
    }, 50);
  }

  waitForTerm(function(term) {
    // Находим WebSocket для отправки данных напрямую
    // TTYD хранит socket в разных местах в зависимости от версии
    var socket = window.socket || window.ws;

    // Альтернатива: используем term._core для доступа к внутренним методам
    // term._core.coreService.triggerDataEvent('\t');

    // Перехватываем Tab до того, как браузер его обработает
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') {
        e.preventDefault();
        e.stopPropagation();

        // Метод 1: Прямая отправка через WebSocket с протоколом TTYD
        // '0' = Command.INPUT в протоколе TTYD
        if (socket && socket.readyState === 1) {
          socket.send('0' + '\t');
          return;
        }

        // Метод 2: Использование внутреннего API xterm.js
        if (term._core && term._core.coreService) {
          term._core.coreService.triggerDataEvent('\t');
          return;
        }

        // Метод 3: Fallback на term.input()
        if (term.input) {
          term.input('\t');
        }
      }
    }, true);
  });
})();
</script>
'''

def inject_tab_fix_script(self, data):
    """Inject Tab fix script into TTYD HTML response."""
    try:
        html = data.decode('utf-8')
        if '</body>' in html:
            html = html.replace('</body>', TAB_FIX_SCRIPT.decode('utf-8') + '</body>')
            return html.encode('utf-8')
        elif '</html>' in html:
            html = html.replace('</html>', TAB_FIX_SCRIPT.decode('utf-8') + '</html>')
            return html.encode('utf-8')
    except:
        pass
    return data
```

## Порядок выполнения

1. Добавить константу `TAB_FIX_SCRIPT` перед классом `TTYDProxyHandler`
2. Добавить метод `inject_tab_fix_script()` в класс `TTYDProxyHandler`
3. Модифицировать `proxy_ttyd_http()` для инъекции скрипта
4. Упростить `tab_handler_script` — оставить только блокировку Tab на родительской странице
5. Обновить виртуальную клавиатуру для использования того же механизма

## Файлы для изменения

| Файл | Изменения |
|------|-----------|
| `app/ttyd_proxy.py` | Основные изменения: TAB_FIX_SCRIPT, inject_tab_fix_script(), proxy_ttyd_http(), tab_handler_script |

## Верификация

### Ручное тестирование

1. Собрать и запустить контейнер:
   ```bash
   docker build -t clihost . && docker run -p 8080:8080 clihost
   ```

2. Открыть http://localhost:8080 в браузере

3. Войти в терминал

4. Протестировать Tab:
   - Набрать `cd /us` и нажать Tab — должно дополниться до `cd /usr/`
   - Набрать `ls /et` и нажать Tab — должно дополниться до `ls /etc/`
   - Убедиться что Tab не переключает фокус на другие элементы страницы

5. Протестировать виртуальную клавиатуру (мобильный режим):
   - Открыть http://localhost:8080?vkbd=true
   - Нажать кнопку Tab — должно работать автодополнение

### Проверка в DevTools

1. Открыть консоль браузера (F12)
2. В iframe выполнить: `window.term` — должен быть объект терминала
3. Проверить наличие WebSocket: `window.socket` или `window.ws`
4. Убедиться что нет ошибок в консоли при нажатии Tab

## Риски и fallback

- **Риск**: TTYD может не экспортировать WebSocket глобально
- **Fallback**: Использовать `term._core.coreService.triggerDataEvent('\t')`

- **Риск**: Версия xterm.js может не иметь `_core`
- **Fallback**: Инспектировать реальную структуру объекта `term` в DevTools

---

## Этап 2: Удаление iframe (если Этап 1 не сработает)

Если инъекция скрипта не решит проблему — переходим к радикальному подходу: полное удаление iframe.

### Суть изменений

Вместо загрузки TTYD в iframe — подавать его HTML/JS/CSS напрямую через прокси с интегрированной аутентификацией.

### Изменения

1. **Извлечь ассеты TTYD**:
   ```bash
   # TTYD встраивает HTML в бинарник, нужно извлечь
   # или собрать из исходников
   ```

2. **Модифицировать `handle_ttyd()`** — вместо генерации iframe-страницы подавать ассеты TTYD напрямую

3. **Перенести аутентификацию** в cookie проверку при WebSocket upgrade

### Плюсы
- Устраняет все проблемы с iframe boundary
- Полный контроль над терминалом
- Tab работает нативно

### Минусы
- Значительный рефакторинг
- Нужно поддерживать синхронизацию ассетов с версией TTYD

---

## Итоговый план действий

| # | Действие | Критерий успеха |
|---|----------|-----------------|
| 1 | Реализовать инъекцию скрипта в TTYD | Tab отправляет `\t` через WebSocket |
| 2 | Тестирование в браузере | Bash completion работает |
| 3 | Если не работает — исследовать структуру `window.term` в DevTools | Найти правильный API |
| 4 | Если ничего не работает — переход к удалению iframe | - |
