#Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
from paramiko.common import OPEN_SUCCEEDED
import re

CTRL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')  # ASCII control chars

def to_printable(s: str) -> str:
    """Remove control characters, keep normal printable text."""
    return CTRL_CHARS_RE.sub('', s)

def decode_bytes(b: bytes) -> str:
    """UTF-8 decode with fallback; then strip control codes."""
    return to_printable(b.decode('utf-8', errors='replace'))




# Constants
logging_format = logging.Formatter("%(message)s")
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = paramiko.RSAKey(filename='server.key')

# Loggers and Logging Files

class ImmediateRotatingFileHandler(RotatingFileHandler):
    def emit(self, record):
        super().emit(record)         # writes + flushes
        try:
            if self.stream and hasattr(self.stream, "fileno"):
                os.fsync(self.stream.fileno())  # force to disk
        except Exception:
            # Avoid crashing the app if fsync fails
            pass

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = ImmediateRotatingFileHandler("audits_funnel.log", maxBytes=2_000_000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler  = ImmediateRotatingFileHandler("audits_creds.log",  maxBytes=2_000_000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# Emulated Shell
def emulated_shell(channel, client_ip):
    prompt = b'work-machine$ '
    channel.send(prompt)

    buf = bytearray()

    while True:
        char = channel.recv(1)
        if not char:
            channel.close()
            break

        # Handle newline/enter (support CR, LF, or CRLF)
        if char in (b'\r', b'\n'):
            # Echo newline(s) consistently
            channel.send(b'\r\n')

            # Decode, clean, and log the command
            raw_cmd = bytes(buf)
            decoded_cmd = decode_bytes(raw_cmd).strip()

            # Log (clean)
            funnel_logger.info(f'Command {decoded_cmd} executed by {client_ip}')

            # Builtins / responses (use decoded str for matching)
            if decoded_cmd == 'exit':
                channel.send(b'Goodbye!\r\n')
                try:
                    channel.close()
                finally:
                    break

            elif decoded_cmd == 'pwd':
                response = b'/usr/local\r\n'
            elif decoded_cmd == 'whoami':
                response = b'corpuser1\r\n'
            elif decoded_cmd == 'ls':
                response = b'jumpbox.conf\r\n'
            elif decoded_cmd == 'cat jumpbox1.conf':
                response = b'file\r\n'
            else:
                # Echo back the cleaned command
                response = decoded_cmd.encode('utf-8', errors='replace') + b'\r\n'

            channel.send(response)
            channel.send(prompt)
            buf.clear()
            continue

        # Handle backspace/delete: \x08 (BS) or \x7f (DEL)
        if char in (b'\x08', b'\x7f'):
            if buf:
                buf.pop()
                # Erase one char on the terminal: backspace, space, backspace
                channel.send(b'\x08 \x08')
            continue

        # Optional: ignore other control chars (e.g., arrow keys start with ESC)
        if char in (b'\x1b',) or (0 <= char[0] < 32 and char not in (b'\t',)):
            # Swallow raw control sequences; you could add rudimentary ESC handling here.
            continue

        # Normal character: add to buffer and echo
        buf += char
        channel.send(char)


class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' + f'username: {username}, ' + f'password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)
    except Exception as error:
        print(error)
        print("!!! Error 116 !!!")

    finally:
        try:
            transport.close()
        except Execption as error:
            print(error)
            print("!!! Error 123 !!!")

# Provision SSH-based Honeypot
def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()


        except Exception as error:
            print(error)
            print("!!! Error 143 !!!")

#honeypot('127.0.0.1', port, username=None, password=None)
