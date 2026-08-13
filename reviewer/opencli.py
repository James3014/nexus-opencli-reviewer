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

    def invoke(self, prompt):
        now = lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        started = now()
        args = [self.executable, 'chatgpt', 'ask', prompt, '--new', '--timeout', str(self.timeout),
                '--site-session', 'ephemeral', '-f', 'json']
        def result(status, raw='', **kwargs):
            return TransportResult(status, raw, executable=self.executable,
                                   profile=self.profile, session_mode='ephemeral', **kwargs)
        try:
            env = os.environ.copy()
            if self.profile:
                env['OPENCLI_PROFILE'] = self.profile
            process = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True, shell=False, env=env,
            )
        except FileNotFoundError:
            return result('OPENCLI_NOT_FOUND', argv=args, started_at=started, finished_at=now())
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
        if timed_out:
            return result('OPENCLI_OUTCOME_UNKNOWN', stdout, argv=args,
                                   outcome_unknown=True, retry_safe=False,
                                   started_at=started, finished_at=now())
        if process.returncode:
            return result('OPENCLI_PROCESS_FAILURE', stdout or stderr, argv=args,
                                   started_at=started, finished_at=now())
        try:
            envelope = json.loads(stdout)
            if (not isinstance(envelope, list) or len(envelope) != 1 or
                    not isinstance(envelope[0], dict) or not isinstance(envelope[0].get('response'), str)):
                raise ValueError
            envelope = envelope[0]
        except (ValueError, json.JSONDecodeError, TypeError):
            return result('OPENCLI_PROCESS_FAILURE', stdout, argv=args,
                                   started_at=started, finished_at=now())
        redacted = self.safe_argv()
        return result('REVIEW_COMPLETED', envelope['response'], version=self.version(),
                               envelope=envelope, argv=redacted, started_at=started, finished_at=now())

    def version(self):
        try:
            result = subprocess.run([self.executable, '--version'], check=False,
                                    capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception:
            return ''
