import json
from pathlib import Path
import subprocess
import sys
import threading
from .store import Problem, require


def watch_memory(child, finished):
    """Darwin has no usable RLIMIT_AS. Monitor the disposable process externally."""
    while not finished.wait(0.05):
        sample = subprocess.run(
            ["/bin/ps", "-o", "rss=", "-p", str(child.pid)],
            capture_output=True,
            timeout=2,
        )
        if (
            sample.returncode == 0
            and sample.stdout.strip()
            and int(sample.stdout) > 384 * 1024
        ):
            child.kill()
            return


def inspect_pdf(content, label=None):
    require(
        0 < len(content) <= 10 * 1024**2, "FILE_SIZE", "Выберите PDF до 10 МБ.", 422
    )
    args = [sys.executable, "-IB", str(Path(__file__).with_name("pdf_worker.py"))]
    if label:
        args.append(label)
    finished = threading.Event()
    with subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"LANG": "C"},
        cwd="/",
    ) as proc:
        monitor = None
        if sys.platform == "darwin":
            monitor = threading.Thread(
                target=watch_memory, args=(proc, finished), daemon=True
            )
            monitor.start()
        try:
            output, _ = proc.communicate(content, timeout=9)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise Problem(
                "FILE_LIMIT",
                "Проверка превысила лимит. Подготовьте более простой PDF.",
                422,
            )
        finally:
            finished.set()
            if monitor:
                monitor.join()
    require(
        proc.returncode == 0,
        "FILE_UNSUPPORTED",
        "Выберите статический PDF до 20 страниц, без пароля, форм, подписей, вложений и активных ссылок.",
        422,
    )
    return json.loads(output)
