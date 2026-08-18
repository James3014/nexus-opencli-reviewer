from __future__ import annotations

import json
import os
import signal
import subprocess
from datetime import datetime, timezone


class TransportResult:
    def __init__(self, status, raw='', version='', envelope=None, argv=None,
                 outcome_unknown=False, retry_safe=False, started_at='', finished_at='',
                 executable='', profile=None, session_mode='ephemeral'):
        self.status = status
        self.raw = raw
        self.version = version
        self.envelope = envelope
        self.argv = argv or []
        self.outcome_unknown = outcome_unknown
        self.retry_safe = retry_safe
        self.started_at = started_at
        self.finished_at = finished_at
        self.executable = executable
        self.profile = profile
        self.session_mode = session_mode


class OpenCLITransport:
    def __init__(self, executable='opencli', timeout=120, process_timeout=None,
                 terminate_grace=2, profile=None):
        self.executable = executable
        self.timeout = timeout
        self.process_timeout = process_timeout if process_timeout is not None else timeout + 60
        self.terminate_grace = terminate_grace
        self.profile = profile

    def safe_argv(self):
        return [self.executable, 'chatgpt', 'ask', '<prompt>', '--new', '--timeout', str(self.timeout),
                '--site-session', 'ephemeral', '-f', 'json']

    @staticmethod
    def _text(value):
        if value is None:
            return ''
        return value.decode(errors='replace') if isinstance(value, bytes) else value

    def _stop_group(self, process, sig):
        try:
            os.killpg(process.pid, sig)
        except (ProcessLookupError, PermissionError):
            try:
                process.send_signal(sig)
            except ProcessLookupError:
                pass

    def _communicate(self, process):
        """Communicate with a process group, terminating and reaping on timeout."""
        try:
            out, err = process.communicate(timeout=self.process_timeout)
            return out, err, False
        except subprocess.TimeoutExpired as expired:
            # The timeout means the outcome is unknown; terminate every process in
            # the POSIX session so descendants cannot retain our pipe descriptors.
            partial_out = self._text(getattr(expired, 'output', None))
            partial_err = self._text(getattr(expired, 'stderr', None))
            self._stop_group(process, signal.SIGTERM)
            try:
                out, err = process.communicate(timeout=self.terminate_grace)
            except subprocess.TimeoutExpired as expired_after_term:
                partial_out += self._text(getattr(expired_after_term, 'output', None))
                partial_err += self._text(getattr(expired_after_term, 'stderr', None))
                self._stop_group(process, signal.SIGKILL)
                out, err = process.communicate()
            return self._text(out) or partial_out, self._text(err) or partial_err, True

    def _run_process(self, args, env):
        try:
            process = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True, shell=False, env=env,
            )
        except FileNotFoundError:
            return None, '', '', False
        try:
            stdout, stderr, timed_out = self._communicate(process)
        finally:
            # communicate() closes captured pipes; close explicitly for custom Popen
            # implementations and guarantee the child has been reaped.
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            if process.poll() is None:
                process.wait()
        return process.returncode, stdout, stderr, timed_out

    @staticmethod
    def _stable_assistant_text(stdout, stable_seconds=6):
        rows = json.loads(stdout)
        if not isinstance(rows, list):
            raise ValueError
        assistants = [
            row for row in rows
            if isinstance(row, dict)
            and row.get('Role') == 'Assistant'
            and isinstance(row.get('Text'), str)
            and row.get('Text')
            and row.get('Generating') is False
            and isinstance(row.get('StableSeconds'), (int, float))
            and row.get('StableSeconds') >= stable_seconds
        ]
        if not assistants:
            raise ValueError
        return assistants[-1]['Text']

    def invoke(self, prompt):
        now = lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        started = now()
        args = [self.executable, 'chatgpt', 'ask', prompt, '--new', '--timeout', str(self.timeout),
                '--site-session', 'ephemeral', '-f', 'json']
        redacted = self.safe_argv()
        def result(status, raw='', **kwargs):
            return TransportResult(status, raw, executable=self.executable,
                                   profile=self.profile, session_mode='ephemeral', **kwargs)
        env = os.environ.copy()
        if self.profile:
            env['OPENCLI_PROFILE'] = self.profile
        returncode, stdout, stderr, timed_out = self._run_process(args, env)
        if returncode is None:
            return result('OPENCLI_NOT_FOUND', argv=redacted, started_at=started, finished_at=now())
        if timed_out:
            return result('OPENCLI_OUTCOME_UNKNOWN', stdout, argv=redacted,
                          outcome_unknown=True, retry_safe=False,
                          started_at=started, finished_at=now())
        if returncode:
            return result('OPENCLI_PROCESS_FAILURE', stdout or stderr, argv=redacted,
                          started_at=started, finished_at=now())
        try:
            ask_rows = json.loads(stdout)
            if (not isinstance(ask_rows, list) or len(ask_rows) != 1 or
                    not isinstance(ask_rows[0], dict) or
                    not isinstance(ask_rows[0].get('response'), str) or
                    not isinstance(ask_rows[0].get('conversationId'), str) or
                    not ask_rows[0].get('conversationId')):
                raise ValueError
            envelope = ask_rows[0]
        except (ValueError, json.JSONDecodeError, TypeError):
            return result('OPENCLI_PROCESS_FAILURE', stdout, argv=redacted,
                          started_at=started, finished_at=now())

        detail_args = [self.executable, 'chatgpt', 'detail', envelope['conversationId'],
                       '--wait', '--stable', '6', '--timeout', str(self.timeout),
                       '--site-session', 'ephemeral', '-f', 'json']
        detail_code, detail_stdout, detail_stderr, detail_timed_out = self._run_process(detail_args, env)
        if detail_code is None or detail_timed_out or detail_code:
            return result('OPENCLI_STABLE_READ_FAILURE', detail_stdout or detail_stderr,
                          envelope=envelope, argv=redacted, retry_safe=False,
                          started_at=started, finished_at=now())
        try:
            stable_text = self._stable_assistant_text(detail_stdout)
        except (ValueError, json.JSONDecodeError, TypeError):
            return result('OPENCLI_STABLE_READ_FAILURE', detail_stdout,
                          envelope=envelope, argv=redacted, retry_safe=False,
                          started_at=started, finished_at=now())
        return result('REVIEW_COMPLETED', stable_text, version=self.version(),
                      envelope=envelope, argv=redacted, started_at=started, finished_at=now())

    def version(self):
        try:
            result = subprocess.run([self.executable, '--version'], check=False,
                                    capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception:
            return ''
