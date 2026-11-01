"""
Персональный сканер утечек и базового аудита безопасности.

Для проверки email нужен API-ключ Have I Been Pwned (HIBP) в переменной
окружения HIBP_API_KEY. Пароли, их хэши и API-ключ в историю не записываются.
"""

import hashlib
import json
import os
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from getpass import getpass
from pathlib import Path


NETWORK_TIMEOUT_SECONDS = 10
USER_AGENT = "PersonalLeakAudit/1.0"
HIBP_PASSWORD_RANGE_URL = "https://api.pwnedpasswords.com/range/"
HIBP_BREACH_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

APP_DIRECTORY = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIRECTORY / "leak_audit_config.json"
HISTORY_PATH = APP_DIRECTORY / "audit_history.json"

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-alt",
}

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def is_valid_email(email: str) -> bool:
    """Проверяет базовый формат email, но не существование почтового ящика."""
    if not email or len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        return False

    local_part, domain = email.rsplit("@", 1)
    return (
        len(local_part) <= 64
        and ".." not in local_part
        and not local_part.startswith(".")
        and not local_part.endswith(".")
        and len(domain) <= 253
    )


def _read_url(url: str, headers: dict[str, str]) -> str:
    """Выполняет HTTPS-запрос и возвращает текст ответа."""
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(
        request, timeout=NETWORK_TIMEOUT_SECONDS
    ) as response:
        return response.read().decode("utf-8")


def check_password_breach(password: str) -> int:
    """
    Возвращает число известных утечек пароля через HIBP k-Anonymity API.

    Полный SHA-1 хэш пароля остаётся локально. API получает только первые
    пять символов хэша; полный хэш сверяется с полученным списком на компьютере.
    """
    if not password:
        raise ValueError("Пароль не должен быть пустым.")

    password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    hash_prefix, hash_suffix = password_hash[:5], password_hash[5:]
    response_text = _read_url(
        HIBP_PASSWORD_RANGE_URL + hash_prefix,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )

    for line in response_text.splitlines():
        if ":" not in line:
            continue
        returned_suffix, count_text = line.strip().split(":", 1)
        if returned_suffix.upper() == hash_suffix:
            try:
                return int(count_text)
            except ValueError as error:
                raise ValueError("API вернул некорректное число совпадений.") from error
    return 0


def check_email_breaches(email: str, api_key: str) -> list[dict]:
    """Возвращает список утечек для email; адрес отправляется сервису HIBP."""
    if not is_valid_email(email):
        raise ValueError("Email имеет некорректный формат.")
    if not api_key.strip():
        raise ValueError("Не задан API-ключ HIBP (переменная HIBP_API_KEY).")

    encoded_email = urllib.parse.quote(email, safe="")
    url = (
        HIBP_BREACH_ACCOUNT_URL
        + encoded_email
        + "?truncateResponse=false"
    )
    request = urllib.request.Request(
        url,
        headers={"hibp-api-key": api_key.strip(), "User-Agent": USER_AGENT},
    )

    try:
        with urllib.request.urlopen(
            request, timeout=NETWORK_TIMEOUT_SECONDS
        ) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return []
        if error.code in (401, 403):
            raise RuntimeError(
                "HIBP отклонил API-ключ или доступ к этому API."
            ) from error
        if error.code == 429:
            raise RuntimeError(
                "HIBP ограничил частоту запросов. Попробуйте позже."
            ) from error
        raise RuntimeError(f"HIBP вернул HTTP-ошибку {error.code}.") from error

    try:
        breaches = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("HIBP вернул ответ в неизвестном формате.") from error
    if not isinstance(breaches, list):
        raise RuntimeError("HIBP вернул ответ неожиданного типа.")
    return breaches


def load_ports(config_path: Path = CONFIG_PATH) -> dict[int, str]:
    """Читает список портов из JSON-конфига или использует значения по умолчанию."""
    if not config_path.exists():
        return DEFAULT_PORTS.copy()

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Не удалось прочитать конфигурацию портов: {error}") from error

    if not isinstance(config, dict) or not isinstance(config.get("ports"), list):
        raise RuntimeError("Конфигурация должна содержать список ports.")

    ports = {}
    for item in config["ports"]:
        if not isinstance(item, dict):
            raise RuntimeError("Каждый порт в конфигурации должен быть объектом.")
        port, service = item.get("port"), item.get("service")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or not isinstance(service, str)
            or not service.strip()
            or port in ports
        ):
            raise RuntimeError("В конфигурации найден некорректный или повторный порт.")
        ports[port] = service.strip()
    if not ports:
        raise RuntimeError("Список портов в конфигурации не должен быть пустым.")
    return ports


def configure_ports(port_text: str, config_path: Path = CONFIG_PATH) -> dict[int, str]:
    """Проверяет введенные номера портов и сохраняет их в JSON-конфигурацию."""
    try:
        port_numbers = [int(value.strip()) for value in port_text.split(",")]
    except ValueError as error:
        raise ValueError("Введите номера портов через запятую, например 22,80,443.") from error

    if (
        not port_numbers
        or any(not 1 <= port <= 65535 for port in port_numbers)
        or len(set(port_numbers)) != len(port_numbers)
    ):
        raise ValueError("Порты должны быть уникальными числами от 1 до 65535.")

    ports = {port: DEFAULT_PORTS.get(port, "custom") for port in port_numbers}
    config = {
        "ports": [
            {"port": port, "service": service}
            for port, service in ports.items()
        ]
    }
    try:
        config_path.write_text(
            json.dumps(config, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise RuntimeError(f"Не удалось сохранить конфигурацию: {error}") from error
    return ports


def scan_local_ports(
    host: str = "127.0.0.1", ports: dict[int, str] | None = None
) -> list[tuple[int, str]]:
    """Проверяет TCP-порты только на локальном компьютере."""
    ports_to_check = load_ports() if ports is None else ports
    open_ports = []
    for port, service_hint in ports_to_check.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(NETWORK_TIMEOUT_SECONDS)
                result = connection.connect_ex((host, port))
        except OSError as error:
            raise RuntimeError(f"Не удалось проверить локальный порт {port}: {error}") from error
        if result == 0:
            open_ports.append((port, service_hint))
    return open_ports


def mask_email(email: str) -> str:
    """Скрывает локальную часть email для локальной истории и отчетов."""
    local_part, domain = email.rsplit("@", 1)
    visible_part = local_part[:1] if local_part else "*"
    return f"{visible_part}***@{domain}"


def perform_check(kind: str, target: str = "", api_key: str = "") -> dict[str, str]:
    """Выполняет проверку и возвращает данные отчета, не сохраняя секреты."""
    if kind == "password":
        count = check_password_breach(target)
        if count:
            details = (
                f"Найдено в утечках: {count} раз(а).\n"
                "Рекомендация: замените пароль везде, где он использовался; "
                "не используйте его повторно и включите MFA."
            )
        else:
            details = (
                "Совпадений в базе HIBP не найдено.\n"
                "Это не гарантирует безопасность пароля. Используйте уникальный "
                "пароль и менеджер паролей."
            )
        subject = "Пароль (не сохраняется)"
        check_name = "Проверка пароля"
    elif kind == "email":
        breaches = check_email_breaches(target, api_key)
        subject = mask_email(target)
        check_name = "Проверка email"
        if not breaches:
            details = (
                "HIBP не сообщил об известных утечках для этого email.\n"
                "Это не доказывает, что адрес никогда не попадал в утечки."
            )
        else:
            breach_lines = [
                f"- {item.get('Name', 'Название не указано')} "
                f"({item.get('BreachDate', 'дата не указана')})"
                for item in breaches
            ]
            details = (
                f"Найдено записей об утечках: {len(breaches)}.\n"
                + "\n".join(breach_lines)
                + "\nРекомендация: смените пароли затронутых сервисов и включите MFA."
            )
    elif kind == "ports":
        ports = scan_local_ports()
        check_name = "Проверка портов localhost"
        subject = "127.0.0.1"
        if not ports:
            details = (
                "На проверенных портах localhost TCP-соединение не установлено.\n"
                "Службы могут работать на других портах или интерфейсах."
            )
        else:
            port_lines = [f"- {port} ({service})" for port, service in ports]
            details = (
                "Принимают TCP-соединения:\n"
                + "\n".join(port_lines)
                + "\nПроверьте, запускали ли вы эти службы намеренно. "
                "Открытый localhost-порт сам по себе не означает доступность извне."
            )
    else:
        raise ValueError("Неизвестный тип проверки.")

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    report = (
        f"Отчет: {check_name}\n"
        f"Время: {timestamp}\n"
        f"Объект: {subject}\n\n"
        f"{details}"
    )
    return {
        "timestamp": timestamp,
        "check": check_name,
        "subject": subject,
        "report": report,
    }


def load_history(history_path: Path = HISTORY_PATH) -> list[dict[str, str]]:
    """Загружает локальную историю; сообщает об ошибках и поврежденных данных."""
    if not history_path.exists():
        return []
    try:
        history = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Не удалось прочитать историю проверок: {error}") from error
    if not isinstance(history, list) or any(
        not isinstance(item, dict)
        or not all(isinstance(item.get(key), str) for key in ("timestamp", "check", "subject", "report"))
        for item in history
    ):
        raise RuntimeError("Файл истории имеет некорректный формат.")
    return history


def save_history(
    record: dict[str, str], history_path: Path = HISTORY_PATH
) -> None:
    """Добавляет отчет в историю; в запись не передаются пароль или API-ключ."""
    history = load_history(history_path)
    history.append(record)
    try:
        history_path.write_text(
            json.dumps(history, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise RuntimeError(f"Не удалось сохранить историю проверок: {error}") from error


def save_report(report: str, output_path: str | Path) -> Path:
    """Сохраняет последний текстовый отчет в выбранный файл."""
    path = Path(output_path).expanduser()
    if not path.suffix:
        path = path.with_suffix(".txt")
    try:
        path.write_text(report + "\n", encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Не удалось сохранить отчет: {error}") from error
    return path


def print_history(history_path: Path = HISTORY_PATH) -> None:
    """Выводит последние записи истории, не раскрывая полный email."""
    history = load_history(history_path)
    if not history:
        print("История пока пуста.")
        return
    print("\nПоследние проверки:")
    for record in history[-20:]:
        print(f"\n{record['timestamp']} — {record['check']} — {record['subject']}")
        print(record["report"].split("\n\n", 1)[-1])


def _run_console_check(kind: str, target: str = "") -> dict[str, str]:
    """Выполняет и показывает проверку, затем сохраняет ее отчет в историю."""
    api_key = os.environ.get("HIBP_API_KEY", "") if kind == "email" else ""
    record = perform_check(kind, target, api_key)
    print("\n" + record["report"])
    save_history(record)
    return record


def _show_error(error: Exception) -> None:
    """Показывает понятное сообщение для ожидаемых ошибок проверки."""
    if isinstance(error, urllib.error.HTTPError):
        print(f"Сервис вернул HTTP-ошибку {error.code}.")
    elif isinstance(error, (urllib.error.URLError, TimeoutError, socket.timeout)):
        print(f"Не удалось связаться с сервисом или сетью: {error}")
        print("Проверьте интернет-соединение и повторите попытку.")
    else:
        print(f"Ошибка: {error}")


def launch_gui() -> None:
    """Запускает необязательный графический интерфейс на Tkinter."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog, ttk
    except ImportError as error:
        raise RuntimeError(
            "Tkinter недоступен в этой установке Python. Используйте консольное меню."
        ) from error

    root = tk.Tk()
    root.title("Персональный сканер утечек")
    root.geometry("720x560")
    root.minsize(580, 420)

    main_frame = ttk.Frame(root, padding=12)
    main_frame.pack(fill="both", expand=True)
    ttk.Label(
        main_frame,
        text="Проверка email отправит адрес сервису Have I Been Pwned.",
        wraplength=680,
    ).pack(anchor="w", pady=(0, 8))

    form = ttk.Frame(main_frame)
    form.pack(fill="x")
    kind_options = {
        "Пароль": "password",
        "Email": "email",
        "Локальные порты": "ports",
    }
    kind_var = tk.StringVar(value="Пароль")
    ttk.Label(form, text="Проверка:").grid(row=0, column=0, sticky="w", padx=(0, 8))
    kind_box = ttk.Combobox(
        form,
        textvariable=kind_var,
        values=tuple(kind_options),
        state="readonly",
        width=16,
    )
    kind_box.grid(row=0, column=1, sticky="w")
    target_var = tk.StringVar()
    target_label = ttk.Label(form, text="Пароль:")
    target_label.grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
    target_entry = ttk.Entry(form, textvariable=target_var, show="*")
    target_entry.grid(row=1, column=1, sticky="ew", pady=(8, 0))
    form.columnconfigure(1, weight=1)

    output = tk.Text(main_frame, height=18, wrap="word", state="disabled")
    output.pack(fill="both", expand=True, pady=10)
    status_var = tk.StringVar(value="Готово.")
    ttk.Label(main_frame, textvariable=status_var).pack(anchor="w")
    latest_report: list[str] = []

    def set_output(text: str) -> None:
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def update_target_field(*_args: object) -> None:
        kind = kind_options[kind_var.get()]
        label = {"password": "Пароль:", "email": "Email:", "ports": "Не требуется:"}[kind]
        target_label.configure(text=label)
        target_entry.configure(show="*" if kind == "password" else "")
        target_entry.configure(state="disabled" if kind == "ports" else "normal")
        if kind == "ports":
            target_var.set("")

    kind_box.bind("<<ComboboxSelected>>", update_target_field)
    update_target_field()

    def run_gui_check() -> None:
        kind = kind_options[kind_var.get()]
        target = target_var.get().strip()
        if kind == "password":
            target = target_var.get()
        if kind == "email" and not messagebox.askyesno(
            "Передача email",
            "Email будет отправлен Have I Been Pwned для проверки. Продолжить?",
            parent=root,
        ):
            return

        run_button.configure(state="disabled")
        status_var.set("Проверка выполняется...")

        def worker() -> None:
            try:
                api_key = os.environ.get("HIBP_API_KEY", "") if kind == "email" else ""
                record = perform_check(kind, target, api_key)
                save_history(record)
                root.after(0, lambda: display_success(record["report"]))
            except (ValueError, RuntimeError, urllib.error.URLError, TimeoutError, OSError) as error:
                root.after(0, lambda error=error: display_error(error))

        def display_success(report: str) -> None:
            latest_report[:] = [report]
            set_output(report)
            status_var.set("Проверка завершена. Отчет добавлен в локальную историю.")
            run_button.configure(state="normal")

        def display_error(error: Exception) -> None:
            status_var.set(f"Ошибка: {error}")
            set_output(f"Проверка не выполнена.\n{error}")
            run_button.configure(state="normal")

        threading.Thread(target=worker, daemon=True).start()

    def export_report() -> None:
        if not latest_report:
            messagebox.showinfo("Нет отчета", "Сначала выполните проверку.", parent=root)
            return
        path = filedialog.asksaveasfilename(
            parent=root,
            title="Сохранить отчет",
            defaultextension=".txt",
            filetypes=(("Текстовый файл", "*.txt"), ("Все файлы", "*.*")),
        )
        if not path:
            return
        try:
            saved_path = save_report(latest_report[0], path)
        except RuntimeError as error:
            messagebox.showerror("Ошибка сохранения", str(error), parent=root)
        else:
            status_var.set(f"Отчет сохранен: {saved_path}")

    def show_gui_history() -> None:
        try:
            history = load_history()
        except RuntimeError as error:
            messagebox.showerror("Ошибка истории", str(error), parent=root)
            return
        if not history:
            set_output("История проверок пока пуста.")
            return
        set_output("\n\n".join(item["report"] for item in history[-20:]))

    def edit_gui_ports() -> None:
        try:
            current_ports = load_ports()
        except RuntimeError as error:
            messagebox.showerror("Ошибка конфигурации", str(error), parent=root)
            return
        current = ",".join(str(port) for port in current_ports)
        entered = simpledialog.askstring(
            "Настройка портов",
            "Введите TCP-порты через запятую (1–65535):",
            initialvalue=current,
            parent=root,
        )
        if entered is None:
            return
        try:
            configured = configure_ports(entered)
        except (ValueError, RuntimeError) as error:
            messagebox.showerror("Ошибка настройки", str(error), parent=root)
            return
        status_var.set("Сохранены порты: " + ", ".join(map(str, configured)))

    buttons = ttk.Frame(main_frame)
    buttons.pack(fill="x")
    run_button = ttk.Button(buttons, text="Запустить проверку", command=run_gui_check)
    run_button.pack(side="left")
    ttk.Button(buttons, text="Сохранить отчет", command=export_report).pack(side="left", padx=6)
    ttk.Button(buttons, text="История", command=show_gui_history).pack(side="left")
    ttk.Button(buttons, text="Настроить порты", command=edit_gui_ports).pack(side="left", padx=6)
    root.mainloop()


def main() -> None:
    """Запускает меню консоли, сохраняя графический интерфейс необязательным."""
    last_report = ""
    print("Персональный сканер утечек и базового аудита безопасности")

    while True:
        print("\nВыберите действие:")
        print("1. Проверить пароль на утечки")
        print("2. Проверить email на утечки (email передается HIBP)")
        print("3. Сканировать локальные порты")
        print("4. Открыть графический интерфейс")
        print("5. Показать историю")
        print("6. Настроить список портов")
        print("7. Сохранить последний отчет")
        print("0. Выход")
        choice = input("> ").strip()

        try:
            if choice == "1":
                record = _run_console_check(
                    "password", getpass("Введите пароль (ввод скрыт): ")
                )
                last_report = record["report"]
            elif choice == "2":
                email = input("Введите email: ").strip()
                if not is_valid_email(email):
                    raise ValueError("Email имеет некорректный формат.")
                if input("Передать адрес сервису HIBP? (да/нет): ").strip().lower() not in (
                    "да", "д", "yes", "y"
                ):
                    print("Проверка отменена.")
                    continue
                record = _run_console_check("email", email)
                last_report = record["report"]
            elif choice == "3":
                record = _run_console_check("ports")
                last_report = record["report"]
            elif choice == "4":
                launch_gui()
            elif choice == "5":
                print_history()
            elif choice == "6":
                current = load_ports()
                print("Текущие порты: " + ", ".join(map(str, current)))
                entered = input("Введите новые порты через запятую: ")
                configured = configure_ports(entered)
                print("Сохранено: " + ", ".join(map(str, configured)))
            elif choice == "7":
                if not last_report:
                    print("Сначала выполните проверку в этом сеансе.")
                    continue
                output_path = input("Путь к файлу отчета: ").strip()
                if not output_path:
                    print("Сохранение отменено.")
                    continue
                saved_path = save_report(last_report, output_path)
                print(f"Отчет сохранен: {saved_path}")
            elif choice == "0":
                print("Работа завершена.")
                break
            else:
                print("Неизвестный пункт меню.")
        except (ValueError, RuntimeError, urllib.error.URLError, TimeoutError, OSError) as error:
            _show_error(error)


if __name__ == "__main__":
    main()
