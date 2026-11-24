#!/usr/bin/env python3
"""Live, local Linux system call explorer."""
import argparse
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

PAGE = Path(__file__).with_name('index.html').read_bytes()
ENTRY = re.compile(rb'^\s*(?:\d+\s+)?([a-zA-Z_][\w]*)\(')


class Trace:
    def __init__(self, options, target, attached=False):
        self.target = target
        self.attached = attached
        self.counts = Counter()
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.ended = self.code = None
        self.error = ''
        self.stopped = False
        reader, writer = os.pipe()
        try:
            self.proc = subprocess.Popen(
                ['strace', '-f', '-s', '0', '-o', f'/proc/self/fd/{writer}', *options],
                pass_fds=(writer,), start_new_session=True,
                stderr=subprocess.PIPE if attached else None)
        except OSError:
            os.close(reader)
            raise
        finally:
            os.close(writer)
        self.worker = threading.Thread(target=self.collect, args=(reader,), daemon=True)
        self.worker.start()

    def collect(self, reader):
        errors = deque(maxlen=3)
        def drain():
            with self.proc.stderr as stream:
                for line in stream:
                    errors.append(line.decode(errors='replace').strip())
        if self.attached:
            diagnostics = threading.Thread(target=drain, daemon=True)
            diagnostics.start()
        with os.fdopen(reader, 'rb') as stream:
            for line in stream:
                match = ENTRY.match(line)
                if match:
                    with self.lock:
                        self.counts[match[1].decode()] += 1
        code = self.proc.wait()
        if self.attached:
            diagnostics.join()
        with self.lock:
            self.code = code
            self.ended = time.monotonic()
            if self.attached and code and not self.stopped:
                self.error = '附加采集失败：' + ' '.join(errors)

    def stop(self):
        with self.lock:
            if self.proc.poll() is not None:
                return
            self.stopped = True
            try:
                if self.attached:
                    self.proc.send_signal(signal.SIGINT)
                else:
                    os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.proc.wait()

    def snapshot(self):
        with self.lock:
            return dict(target=self.target, counts=dict(self.counts), code=self.code,
                        seconds=(self.ended or time.monotonic()) - self.started,
                        error=self.error, stopped=self.stopped, attached=self.attached)


def launch(program, arguments):
    executable = shutil.which(os.path.expanduser(program))
    if not executable or not os.path.isfile(executable):
        raise ValueError('找不到可执行文件，请检查路径和执行权限。')
    return Trace(['--', executable, *arguments], program)


def browse(directory):
    folder = Path(directory or '.').expanduser().resolve(strict=True)
    entries = []
    for item in folder.iterdir():
        is_dir = item.is_dir()
        if is_dir or (item.is_file() and os.access(item, os.X_OK)):
            entries.append(dict(name=item.name, path=str(item), directory=is_dir))
    entries.sort(key=lambda e: (not e['directory'], e['name']))
    return dict(folder=str(folder), parent=str(folder.parent), entries=entries)


def process_info(pid):
    # comm (field 2) may itself contain spaces or closing parentheses.
    stat = Path(f'/proc/{pid}/stat').read_bytes()
    head, _, tail = stat.rpartition(b')')
    fields = tail.split()  # Starts at field 3 (state).
    if fields[0] in (b'Z', b'X'):
        raise ProcessLookupError('进程已退出。')
    name = head.partition(b'(')[2].decode(errors='replace')
    return dict(pid=pid, name=name, started=fields[19].decode())


def processes():
    entries = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid():
            continue
        try:
            entries.append(process_info(int(path.name)))
        except OSError:
            continue  # Process exited or is inaccessible to this user.
    return sorted(entries, key=lambda item: (item['name'].casefold(), item['pid']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    session_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def respond(self, data, status=200, mime='application/json'):
            if mime == 'application/json':
                data = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def local_request(self):
            port = self.server.server_port
            allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if port == 80:
                allowed.update({'localhost', '127.0.0.1'})
            return self.headers.get('Host') in allowed

        def do_GET(self):
            if not self.local_request():
                return self.respond({}, 403)
            path = urlsplit(self.path)
            if path.path == '/':
                return self.respond(PAGE, mime='text/html; charset=utf-8')
            if path.path == '/api':
                with session_lock:
                    return self.respond(trace.snapshot())
            if path.path == '/processes':
                return self.respond(processes())
            if path.path == '/files':
                try:
                    return self.respond(browse(parse_qs(path.query).get('dir', ['.'])[0]))
                except (ValueError, RuntimeError, OSError) as exc:
                    return self.respond(dict(error=str(exc)), 400)
            self.send_error(404)

        def do_POST(self):
            nonlocal trace
            if not self.local_request() or self.headers.get('X-Explorer') != '1':
                return self.respond({}, 403)
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 65536:
                    raise ValueError('请求长度无效。')
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise ValueError('请求格式无效。')
                with session_lock:
                    if self.path == '/stop':
                        trace.stop()
                    elif self.path not in ('/launch', '/attach'):
                        return self.respond({}, 404)
                    elif trace.proc.poll() is None:
                        return self.respond(dict(error='请先停止当前采集。'), 409)
                    elif self.path == '/launch':
                        program, arguments = data.get('program'), data.get('arguments', '')
                        if not isinstance(program, str) or not isinstance(arguments, str):
                            raise ValueError('请输入程序路径及参数。')
                        trace = launch(program, shlex.split(arguments))
                    else:
                        pid = int(data.get('pid', 0))
                        if pid <= 0 or pid == os.getpid() or not Path(f'/proc/{pid}').is_dir():
                            raise ValueError('目标进程不可用，请刷新进程列表。')
                        info = process_info(pid)
                        if 'started' in data and data['started'] != info['started']:
                            raise ValueError('原进程已退出，请刷新进程列表。')
                        trace = Trace(['-p', str(pid)], f"{info['name']} (PID {pid})", attached=True)
                self.respond({})
            except (OSError, ValueError, TypeError) as exc:
                self.respond(dict(error=str(exc)), 400)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
        try:
            if command:
                trace = launch(command[0], command[1:])
            else:
                demo = 'import os,time\nwhile True:\n os.listdir("."); os.stat("."); time.sleep(0.1)'
                trace = Trace(['--', sys.executable, '-c', demo], '内置目录扫描示例')
        except (OSError, ValueError) as exc:
            parser.exit(1, f'{exc}\n')
        print(f'打开 http://127.0.0.1:{server.server_port}   Ctrl+C 结束会话', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            with session_lock:
                trace.stop()


if __name__ == '__main__':
    main()
