"""Test util helpers."""

import getpass
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import typing as _t  # noqa: WPS111  # project typing alias
from contextlib import contextmanager

from pylibsshext.session import Session


IS_MACOS = sys.platform == 'darwin'
_MACOS_RECONNECT_ATTEMPT_DELAY = 0.06
_LINUX_RECONNECT_ATTEMPT_DELAY = 0.002
_DEFAULT_RECONNECT_ATTEMPT_DELAY = (
    _MACOS_RECONNECT_ATTEMPT_DELAY
    if IS_MACOS
    else _LINUX_RECONNECT_ATTEMPT_DELAY
)


def wait_for_svc_ready_state(
    host,
    port,
    clientkey_path,
    max_conn_attempts=40,
    reconnect_attempt_delay=_DEFAULT_RECONNECT_ATTEMPT_DELAY,
):
    """Verify that the service is up and running.

    :param host: Hostname.
    :type host: str

    :param port: Port.
    :type port: int

    :param clientkey_path: Path to the client private key.
    :type clientkey_path: pathlib.Path

    :param max_conn_attempts: Number of tries when connecting.
    :type max_conn_attempts: int

    :param reconnect_attempt_delay: Time to sleep between retries.
    :type reconnect_attempt_delay: float

    # noqa: DAR401
    """
    cmd = [
        '/usr/bin/ssh',
        '-F/dev/null',  # or -Fnone
        '-oConnectTimeout=1',
        '-oIdentitiesOnly=yes',
        '-oIdentityAgent=/dev/null',
        f'-oIdentityFile={clientkey_path!s}',
        '-oPasswordAuthentication=no',
        f'-oPort={port!s}',
        '-oPreferredAuthentications=publickey',
        '-oStrictHostKeyChecking=no',
        f'-oUser={getpass.getuser()!s}',
        '-oUserKnownHostsFile=/dev/null',
        host,
        '--',
        'exit 0',
    ]

    attempts = 0
    rc = -1
    while attempts < max_conn_attempts and rc != 0:
        check_result = subprocess.run(cmd, check=False)
        rc = check_result.returncode
        if rc != 0:
            time.sleep(reconnect_attempt_delay)

    if rc != 0:
        timeout_msg = 'Timed out waiting for a successful connection'
        raise TimeoutError(timeout_msg)


def ensure_ssh_session_connected(
    ssh_session,
    sshd_addr,
    ssh_clientkey_path,
    ssh_session_retries=0,
):
    """Attempt connecting to the SSH server until successful.

    :param ssh_session: SSH session object.
    :type ssh_session: pylibsshext.session.Session

    :param sshd_addr: Hostname and port tuple.
    :type sshd_addr: tuple[str, int]

    :param ssh_clientkey_path: Hostname and port tuple.
    :type ssh_clientkey_path: pathlib.Path
    """
    hostname, port = sshd_addr
    ssh_session.connect(
        host=hostname,
        port=port,
        user=getpass.getuser(),
        private_key=ssh_clientkey_path.read_bytes(),
        host_key_checking=False,
        look_for_keys=False,
        open_session_retries=ssh_session_retries,
    )


@contextmanager
def paused_ssh_session(
    sshd_addr: tuple[str, int],
    ssh_clientkey_path: pathlib.Path,
) -> _t.Iterator[Session]:
    """Provide an authenticated session with its SSH transport paused.

    :param sshd_addr: Address of the test SSH server.
    :param ssh_clientkey_path: Private key for the test SSH server.
    :yields: An authenticated session that cannot receive server replies.
    """
    host, port = sshd_addr
    command = [
        '/usr/bin/ssh',
        '-F/dev/null',
        '-oBatchMode=yes',
        '-oStrictHostKeyChecking=no',
        '-oUserKnownHostsFile=/dev/null',
        '-oIdentitiesOnly=yes',
        '-oIdentityAgent=none',
        '-i',
        str(ssh_clientkey_path),
        '-p',
        str(port),
        '-W',
        f'{host}:{port}',
        f'{getpass.getuser()}@{host}',
    ]
    client, transport = socket.socketpair()
    ssh_session = Session()
    with (
        client,
        transport,
        subprocess.Popen(
            command,
            stdin=transport,
            stdout=transport,
        ) as proxy,
    ):
        try:  # noqa: WPS229  # keep transport cleanup around connection and test
            ssh_session.connect(
                fd=client.fileno(),
                host=host,
                user=getpass.getuser(),
                private_key=ssh_clientkey_path.read_bytes(),
                host_key_checking=False,
                look_for_keys=False,
            )
            proxy.send_signal(signal.SIGSTOP)
            # Wait for the proxy to stop before sending a channel-open request.
            _, stop_status = os.waitpid(proxy.pid, os.WUNTRACED)
            assert os.WIFSTOPPED(stop_status)
            yield ssh_session
        finally:
            proxy.send_signal(signal.SIGCONT)
            try:  # noqa: WPS505  # terminate the proxy even if session cleanup fails
                ssh_session.close()
            finally:
                proxy.terminate()
