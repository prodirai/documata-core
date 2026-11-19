import json
from pathlib import Path
import subprocess
import sys
from .store import Problem, require

def inspect_pdf(content, label=None):
    require(0<len(content)<=10*1024**2,"FILE_SIZE","Выберите PDF до 10 МБ.",422)
    args = [sys.executable,"-IB",str(Path(__file__).with_name("pdf_worker.py"))]
    if label:
        args.append(label)
    try:
        run = subprocess.run(args,input=content,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=9,env={"LANG":"C"},cwd="/")
    except subprocess.TimeoutExpired:
        raise Problem("FILE_LIMIT","Проверка превысила лимит. Подготовьте более простой PDF.",422)
    require(run.returncode==0,"FILE_UNSUPPORTED","Выберите статический PDF до 20 страниц, без пароля, форм, подписей, вложений и активных ссылок.",422)
    return json.loads(run.stdout)
