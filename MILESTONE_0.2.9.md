# Milestone 0.2.9 — Fix mouse wheel scroll in TTYD

## Проблема

В веб-терминале TTYD скролл колёсиком мыши генерирует ANSI-последовательности `\x1b[A` / `\x1b[B` (ArrowUp/ArrowDown). Это перемещает курсор в строке ввода bash/zsh вместо прокрутки буфера экрана.

Корневая причина: xterm.js по умолчанию транслирует события `wheel` в escape-последовательности клавиш-стрелок.

## Решение

Добавить `wheel` event listener в `TAB_FIX_SCRIPT` — JavaScript, инжектируемый в TTYD HTML до загрузки xterm.js.

**Логика обработчика:**
- `capture: true` — срабатывает раньше, чем viewport xterm.js
- `passive: false` — позволяет вызвать `e.preventDefault()`
- **Normal screen** (bash/zsh): вызывает `term.scrollLines(n)` и блокирует дефолтное поведение
- **Alternate screen** (vim/less/htop): пропускает событие без изменений (xterm.js отправит ArrowUp/ArrowDown программе)

Определение alternate screen через `term.buffer.active.type === 'alternate'` (публичное API xterm.js 4+).

## Изменённые файлы

| Файл | Изменение |
|------|-----------|
| `app/ttyd_proxy.py` | Добавлен `wheel` listener в `TAB_FIX_SCRIPT` |

## Проверка

```bash
docker build -t clihost . && docker run -p 8080:8080 clihost
```

1. Открыть http://localhost:8080, войти, открыть терминал
2. Ввести несколько команд → нажать Enter несколько раз → прокрутить колёсиком вверх — буфер должен скролиться
3. `vim /etc/passwd` → скролл в vim должен перемещать курсор по файлу (не прокручивать буфер)
4. `less /etc/passwd` → скролл должен листать файл
