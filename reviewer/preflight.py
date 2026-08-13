from __future__ import annotations

import json
import os
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class PreflightResult:
    status: str
    profile: dict | None = None
    profiles: list | None = None
    detail: str = ''
    argv: list[str] | None = None


class OpenCLIPreflight:
    """Read-only OpenCLI/browser readiness checks; never invokes ask/send/model."""

    def __init__(self, executable='opencli', timeout=10, terminate_grace=1):
        self.executable = executable
        self.timeout = timeout
        self.terminate_grace = terminate_grace

    def _run(self, args):
        try:
            p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True,
                                 shell=False)
        except FileNotFoundError:
            return None, '', 'OPENCLI_NOT_FOUND'
        try:
            try:
                out, err = p.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    p.send_signal(signal.SIGTERM)
                try:
                    out, err = p.communicate(timeout=self.terminate_grace)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        p.kill()
                    out, err = p.communicate()
                return p, out or err, 'OPENCLI_TRANSPORT_FAILURE'
            return p, out if p.returncode == 0 else (out or err), None if p.returncode == 0 else 'OPENCLI_TRANSPORT_FAILURE'
        finally:
            for stream in (p.stdout, p.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            if p.poll() is None:
                p.wait()

    @staticmethod
    def _json(raw):
        try:
            return json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _connected(profile):
        if not isinstance(profile, dict):
            return False
        value = profile.get('connected', profile.get('isConnected'))
        if value is True:
            return True
        return str(profile.get('status', '')).lower() in {'connected', 'active', 'ready', 'logged_in'}

    @staticmethod
    def _profiles(raw):
        """Normalize OpenCLI 1.8.6's human-only ``profile list`` output."""
        rows = []
        for line in raw.splitlines():
            text = line.strip()
            if not text or text.lower().startswith('connected browser bridge profiles'):
                continue
            if 'connected' not in text.lower():
                continue
            profile_id = text.split()[0]
            rows.append({
                'id': profile_id,
                'connected': True,
                'default': ' default ' in f' {text.lower()} ',
                'display': text,
            })
        return rows

    def run(self):
        profile_args = [self.executable, 'profile', 'list']
        proc, raw, error = self._run(profile_args)
        if error:
            return PreflightResult(error, detail=raw, argv=profile_args)
        payload = self._json(raw)
        profiles = payload.get('profiles', payload) if isinstance(payload, dict) else payload
        if not isinstance(profiles, list):
            profiles = self._profiles(raw)
        connected = [p for p in profiles if self._connected(p)]
        if not connected:
            return PreflightResult('BROWSER_BRIDGE_REQUIRED', profiles=profiles, argv=profile_args)
        if len(connected) != 1:
            return PreflightResult('PROFILE_SELECTION_AMBIGUOUS', profiles=profiles,
                                   detail=f'{len(connected)} connected profiles', argv=profile_args)
        profile = connected[0]
        status_args = [self.executable, 'chatgpt', 'status', '--site-session', 'ephemeral', '-f', 'json']
        _, status_raw, error = self._run(status_args)
        if error:
            return PreflightResult(error, profile=profile, profiles=profiles, detail=status_raw, argv=status_args)
        status = self._json(status_raw)
        if isinstance(status, list) and len(status) == 1 and isinstance(status[0], dict):
            status = status[0]
        if not isinstance(status, dict):
            return PreflightResult('OPENCLI_TRANSPORT_FAILURE', profile=profile, profiles=profiles,
                                   detail='invalid status JSON', argv=status_args)
        normalized = {str(k).lower(): value for k, value in status.items()}
        state = ' '.join(str(normalized.get(k, '')) for k in ('status', 'state', 'error', 'message', 'login')).lower()
        if any(x in state for x in ('challenge', 'captcha', 'verification')):
            code = 'CHATGPT_CHALLENGE'
        elif any(x in state for x in ('quota', 'rate limit', 'rate_limit', 'too many')):
            code = 'CHATGPT_QUOTA_OR_RATE_LIMIT'
        elif normalized.get('logged_in') is False or normalized.get('authenticated') is False or str(normalized.get('login', '')).lower() in {'no', 'false'} or any(x in state for x in ('not logged', 'unauthenticated', 'login required')):
            code = 'CHATGPT_NOT_LOGGED_IN'
        else:
            code = 'READY'
        return PreflightResult(code, profile=profile, profiles=profiles, detail=status_raw, argv=status_args)


def preflight_opencli(executable='opencli', timeout=10, terminate_grace=1):
    return OpenCLIPreflight(executable, timeout, terminate_grace).run()
