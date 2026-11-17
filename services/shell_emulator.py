"""Stateful fake BusyBox shell.

Each connection gets its own ``ShellSession`` with a small in-memory
filesystem, so the decoy adapts to what the attacker does: a "downloaded"
file shows up in ``ls``, ``cd`` changes the prompt, ``rm`` removes things.

Nothing here touches the real system. No command is executed, no URL is
fetched and no file is written to disk.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from urllib.parse import urlparse

HOSTNAME = "iot-camera"
MAX_FILES = 64
MAX_FILE_BYTES = 4096
MAX_CHAINED_COMMANDS = 20

_BASE_DIRS = {
    "/", "/bin", "/dev", "/etc", "/home", "/home/admin", "/mnt", "/opt",
    "/opt/camera", "/proc", "/root", "/sbin", "/sys", "/tmp", "/usr",
    "/usr/bin", "/var", "/var/log", "/var/run",
}

_BASE_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/sh\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
        "camera:x:1001:1001:camera:/opt/camera:/bin/false\n"
    ),
    "/etc/hostname": f"{HOSTNAME}\n",
    "/etc/version": "IoT-CAM-3000 firmware 1.0.7 (build 20210412)\n",
    "/etc/resolv.conf": "nameserver 192.168.1.1\n",
    "/proc/cpuinfo": (
        "processor\t: 0\n"
        "model name\t: ARMv7 Processor rev 5 (v7l)\n"
        "BogoMIPS\t: 1594.16\n"
        "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4\n"
        "Hardware\t: Hisilicon Hi3516CV300\n"
    ),
    "/proc/meminfo": (
        "MemTotal:          58620 kB\n"
        "MemFree:           12404 kB\n"
        "Buffers:            3920 kB\n"
        "Cached:            18112 kB\n"
    ),
    "/proc/version": (
        "Linux version 4.4.0 (build@fw-builder) (gcc version 6.3.0) "
        "#1 SMP Mon Apr 12 09:14:02 CST 2021\n"
    ),
    "/proc/mounts": (
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / squashfs ro,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,relatime 0 0\n"
    ),
    "/opt/camera/camera.conf": "rtsp_port=554\nresolution=1920x1080\nfps=25\n",
    "/var/log/messages": (
        "Jan  1 00:00:12 iot-camera syslogd started: BusyBox v1.24.1\n"
        "Jan  1 00:00:19 iot-camera camera-daemon[72]: stream ready\n"
    ),
}

_READ_DENIED = {"/etc/shadow"}

_BUSYBOX_BANNER = (
    "BusyBox v1.24.1 (2021-04-12 09:10:33 CST) multi-call binary.\n"
    "Usage: busybox [function [arguments]...]\n"
)

_PS = (
    "  PID USER       VSZ STAT COMMAND\n"
    "    1 root      1532 S    init\n"
    "   54 root      1528 S    /sbin/syslogd -n\n"
    "   72 root     21540 S    /usr/bin/camera-daemon\n"
    "   88 root      3104 S    /usr/bin/httpd -p 80\n"
    "  101 root      1536 S    telnetd\n"
    "  140 root      1540 S    -sh\n"
)

_IFCONFIG = (
    "eth0      Link encap:Ethernet  HWaddr 00:16:3E:11:22:33\n"
    "          inet addr:192.168.1.64  Bcast:192.168.1.255  Mask:255.255.255.0\n"
    "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
    "lo        Link encap:Local Loopback\n"
    "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
)

_NETSTAT = (
    "Active Internet connections (servers and established)\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
    "tcp        0      0 0.0.0.0:554             0.0.0.0:*               LISTEN\n"
    "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\n"
)

_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")


class ShellSession:
    def __init__(self, username: str = "root") -> None:
        self.username = username or "root"
        self.cwd = "/root" if self.username == "root" else "/tmp"
        self.dirs = set(_BASE_DIRS)
        self.files: dict[str, str] = dict(_BASE_FILES)
        self.user_files: set[str] = set()
        self.history: list[str] = []
        self.closed = False

    # ------------------------------------------------------------------ helpers

    @property
    def prompt(self) -> str:
        home = "/root" if self.username == "root" else f"/home/{self.username}"
        shown = "~" if self.cwd == home else self.cwd
        marker = "#" if self.username == "root" else "$"
        return f"{self.username}@{HOSTNAME}:{shown}{marker} "

    def _resolve(self, path: str) -> str:
        if path.startswith("~"):
            path = "/root" + path[1:]
        return posixpath.normpath(posixpath.join(self.cwd, path))

    def _write(self, path: str, content: str) -> bool:
        if path not in self.files and len(self.user_files) >= MAX_FILES:
            return False
        if posixpath.dirname(path) not in self.dirs:
            return False
        self.files[path] = content[:MAX_FILE_BYTES]
        self.user_files.add(path)
        return True

    def _children(self, directory: str) -> list[str]:
        prefix = directory.rstrip("/") + "/"
        names = set()
        for path in list(self.dirs) + list(self.files):
            if path != directory and path.startswith(prefix):
                names.add(path[len(prefix):].split("/", 1)[0])
        return sorted(names)

    # --------------------------------------------------------------- execution

    def run(self, line: str) -> str:
        """Run one input line (possibly several chained commands)."""
        line = line.strip()
        if not line:
            return ""
        self.history.append(line)

        output = []
        for command in _SPLIT.split(line)[:MAX_CHAINED_COMMANDS]:
            if not command or self.closed:
                continue
            output.append(self._run_single(command))
        return "".join(output)

    def _run_single(self, command: str) -> str:
        # Only the first stage of a pipeline produces "output".
        command = command.split("|", 1)[0].strip().rstrip("&").strip()

        # Drop stderr plumbing such as "2>&1" and "2>/dev/null".
        command = re.sub(r"\s*\d?>\s*&\d|\s*2>\s*\S+", "", command).strip()

        redirect = None
        match = re.search(r"\s*(>>?)\s*(\S+)\s*$", command)
        if match and not command.startswith(("wget", "curl")):
            redirect = (match.group(1), match.group(2))
            command = command[: match.start()].strip()

        try:
            argv = shlex.split(command)
        except ValueError:
            argv = command.split()
        if not argv:
            return ""

        name, args = argv[0], argv[1:]
        if name.startswith("/"):
            base = posixpath.basename(name)
            if posixpath.dirname(name) in {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}:
                name = base

        result = self._dispatch(name, args, command)

        if redirect is not None:
            operator, target = redirect
            path = self._resolve(target)
            if path.startswith("/dev/"):
                return ""
            existing = self.files.get(path, "") if operator == ">>" else ""
            if not self._write(path, existing + result):
                return f"-sh: can't create {target}: No space left on device\n"
            return ""
        return result

    def _dispatch(self, name: str, args: list[str], raw: str) -> str:
        if name == "busybox":
            if not args:
                return _BUSYBOX_BANNER
            if args[0].isupper() or args[0] not in _COMMANDS:
                # Bots (e.g. Mirai) probe with a random applet name and look
                # for this exact reply to confirm a BusyBox shell.
                return f"{args[0]}: applet not found\n"
            name, args = args[0], args[1:]

        if name.startswith("./") or (name.startswith("/") and "/" in name[1:]):
            path = self._resolve(name)
            if path in self.files:
                return ""
            return f"-sh: {name}: not found\n"

        handler = _COMMANDS.get(name)
        if handler is None:
            return f"-sh: {name}: not found\n"
        return handler(self, args)

    # ---------------------------------------------------------------- commands

    def _exit(self, args):
        self.closed = True
        return ""

    def _silent(self, args):
        return ""

    def _help(self, args):
        return (
            "Built-in commands:\n"
            "  . : cd echo exit export help history kill pwd set umask\n"
        )

    def _whoami(self, args):
        return f"{self.username}\n"

    def _id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.username}) gid=1000({self.username})\n"

    def _uname(self, args):
        flags = "".join(arg.lstrip("-") for arg in args if arg.startswith("-"))
        if "a" in flags:
            return f"Linux {HOSTNAME} 4.4.0 #1 SMP Mon Apr 12 09:14:02 CST 2021 armv7l GNU/Linux\n"
        if "m" in flags:
            return "armv7l\n"
        if "r" in flags:
            return "4.4.0\n"
        if "n" in flags:
            return f"{HOSTNAME}\n"
        return "Linux\n"

    def _hostname(self, args):
        return f"{HOSTNAME}\n"

    def _pwd(self, args):
        return f"{self.cwd}\n"

    def _cd(self, args):
        target = self._resolve(args[0]) if args else "/root"
        if target in self.dirs:
            self.cwd = target
            return ""
        if target in self.files:
            return f"-sh: cd: can't cd to {args[0]}: Not a directory\n"
        return f"-sh: cd: can't cd to {args[0]}: No such file or directory\n"

    def _ls(self, args):
        flags = "".join(arg[1:] for arg in args if arg.startswith("-"))
        targets = [arg for arg in args if not arg.startswith("-")] or ["."]
        lines = []
        for target in targets:
            path = self._resolve(target)
            if path in self.files:
                names = [posixpath.basename(path)]
                parent = posixpath.dirname(path)
            elif path in self.dirs:
                names = self._children(path)
                parent = path
            else:
                lines.append(f"ls: {target}: No such file or directory")
                continue
            if "a" in flags and path in self.dirs:
                names = [".", ".."] + names
            for entry in names:
                full = posixpath.normpath(posixpath.join(parent, entry))
                if "l" in flags:
                    if full in self.files:
                        size = len(self.files[full])
                        mode = "-rwxr-xr-x" if full in self.user_files else "-rw-r--r--"
                    else:
                        size, mode = 4096, "drwxr-xr-x"
                    lines.append(f"{mode}    1 root     root     {size:>8} Jan  1 00:00 {entry}")
                else:
                    lines.append(entry)
        return "\n".join(lines) + "\n" if lines else ""

    def _cat(self, args):
        output = []
        for arg in args:
            if arg.startswith("-"):
                continue
            path = self._resolve(arg)
            if path in _READ_DENIED:
                output.append(f"cat: can't open '{arg}': Permission denied\n")
            elif path in self.files:
                output.append(self.files[path])
            elif path in self.dirs:
                output.append("cat: read error: Is a directory\n")
            else:
                output.append(f"cat: can't open '{arg}': No such file or directory\n")
        return "".join(output)

    def _echo(self, args):
        newline = True
        if args and args[0] in {"-n", "-e", "-ne", "-en"}:
            newline = "n" not in args[0]
            args = args[1:]
        return " ".join(args) + ("\n" if newline else "")

    def _download(self, args):
        """Pretend to fetch a file. No network request is ever made."""
        url = next((arg for arg in args if "://" in arg), None)
        output_name = None
        for flag in ("-O", "-o"):
            if flag in args and args.index(flag) + 1 < len(args):
                output_name = args[args.index(flag) + 1]
        if url is None:
            positional = [arg for arg in args if not arg.startswith("-")]
            if not positional:
                return "wget: missing URL\n"
            url = "http://" + positional[0]

        parsed = urlparse(url)
        host = parsed.hostname or "unknown"
        name = output_name or posixpath.basename(parsed.path) or "index.html"
        if name == "-":
            return ""
        if not self._write(self._resolve(name), "\x7fELF"):
            return f"wget: can't open '{name}': No space left on device\n"
        return (
            f"Connecting to {host} ({host}:{parsed.port or 80})\n"
            f"{name:<20} 100% |*******************************| 48216   0:00:00 ETA\n"
        )

    def _tftp(self, args):
        name = None
        for flag in ("-r", "-l"):
            if flag in args and args.index(flag) + 1 < len(args):
                name = args[args.index(flag) + 1]
        if name is None:
            return "tftp: usage: tftp -g -r FILE HOST\n"
        self._write(self._resolve(posixpath.basename(name)), "\x7fELF")
        return ""

    def _chmod(self, args):
        targets = [arg for arg in args[1:] if not arg.startswith("-")]
        for target in targets:
            path = self._resolve(target)
            if path not in self.files and path not in self.dirs:
                return f"chmod: {target}: No such file or directory\n"
        return ""

    def _rm(self, args):
        output = []
        for arg in args:
            if arg.startswith("-"):
                continue
            path = self._resolve(arg)
            if path in self.user_files:
                self.user_files.discard(path)
                self.files.pop(path, None)
            elif path in self.files or path in self.dirs:
                if "-rf" not in args and "-f" not in args and "-fr" not in args:
                    output.append(f"rm: can't remove '{arg}': Read-only file system\n")
            elif not any(flag in args for flag in ("-f", "-rf", "-fr")):
                output.append(f"rm: can't remove '{arg}': No such file or directory\n")
        return "".join(output)

    def _touch(self, args):
        for arg in args:
            if not arg.startswith("-"):
                path = self._resolve(arg)
                if path not in self.files:
                    self._write(path, "")
        return ""

    def _mkdir(self, args):
        for arg in args:
            if arg.startswith("-"):
                continue
            path = self._resolve(arg)
            if posixpath.dirname(path) in self.dirs and len(self.dirs) < len(_BASE_DIRS) + MAX_FILES:
                self.dirs.add(path)
        return ""

    def _copy(self, args):
        paths = [arg for arg in args if not arg.startswith("-")]
        if len(paths) < 2:
            return "cp: missing file operand\n"
        source, target = self._resolve(paths[0]), self._resolve(paths[1])
        if source not in self.files:
            return f"cp: can't stat '{paths[0]}': No such file or directory\n"
        if target in self.dirs:
            target = posixpath.join(target, posixpath.basename(source))
        self._write(target, self.files[source])
        return ""

    def _move(self, args):
        paths = [arg for arg in args if not arg.startswith("-")]
        result = self._copy(args)
        if not result and len(paths) >= 2:
            source = self._resolve(paths[0])
            if source in self.user_files:
                self.user_files.discard(source)
                self.files.pop(source, None)
        return result.replace("cp:", "mv:")

    def _sh(self, args):
        scripts = [arg for arg in args if not arg.startswith("-")]
        if not scripts:
            return ""
        if self._resolve(scripts[0]) in self.files:
            return ""
        return f"sh: can't open '{scripts[0]}': No such file or directory\n"

    def _ps(self, args):
        return _PS

    def _ifconfig(self, args):
        return _IFCONFIG

    def _ip(self, args):
        if args and args[0].startswith("r"):
            return "default via 192.168.1.1 dev eth0\n192.168.1.0/24 dev eth0 scope link\n"
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    link/ether 00:16:3e:11:22:33 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.1.64/24 brd 192.168.1.255 scope global eth0\n"
        )

    def _netstat(self, args):
        return _NETSTAT

    def _free(self, args):
        return (
            "             total       used       free     shared    buffers     cached\n"
            "Mem:         58620      46216      12404          0       3920      18112\n"
        )

    def _df(self, args):
        return (
            "Filesystem           1K-blocks      Used Available Use% Mounted on\n"
            "/dev/root                 9216      9216         0 100% /\n"
            "tmpfs                    29308       112     29196   0% /tmp\n"
        )

    def _uptime(self, args):
        return " 00:41:07 up 12 days,  3:52,  load average: 0.08, 0.11, 0.09\n"

    def _mount(self, args):
        return self.files["/proc/mounts"]

    def _date(self, args):
        return "Thu Jan  1 00:41:07 UTC 1970\n"

    def _env(self, args):
        return (
            f"USER={self.username}\nHOME=/root\nSHELL=/bin/sh\n"
            "PATH=/sbin:/usr/sbin:/bin:/usr/bin\nTERM=vt100\n"
            f"PWD={self.cwd}\n"
        )

    def _history(self, args):
        return "".join(f"{index:>5}  {entry}\n" for index, entry in enumerate(self.history, 1))

    def _reboot(self, args):
        self.closed = True
        return "The system is going down NOW!\n"

    def _passwd(self, args):
        return "passwd: password for root is unchanged\n"

    def _denied(self, args):
        return "Permission denied\n"


_COMMANDS = {
    "exit": ShellSession._exit, "quit": ShellSession._exit, "logout": ShellSession._exit,
    "help": ShellSession._help,
    "whoami": ShellSession._whoami, "id": ShellSession._id, "uname": ShellSession._uname,
    "hostname": ShellSession._hostname, "pwd": ShellSession._pwd, "cd": ShellSession._cd,
    "ls": ShellSession._ls, "ll": ShellSession._ls, "cat": ShellSession._cat,
    "head": ShellSession._cat, "tail": ShellSession._cat, "more": ShellSession._cat,
    "echo": ShellSession._echo,
    "wget": ShellSession._download, "curl": ShellSession._download,
    "tftp": ShellSession._tftp, "ftpget": ShellSession._tftp,
    "chmod": ShellSession._chmod, "chown": ShellSession._silent,
    "rm": ShellSession._rm, "touch": ShellSession._touch, "mkdir": ShellSession._mkdir,
    "cp": ShellSession._copy, "mv": ShellSession._move,
    "sh": ShellSession._sh, "bash": ShellSession._sh, "ash": ShellSession._sh,
    "ps": ShellSession._ps, "top": ShellSession._ps,
    "ifconfig": ShellSession._ifconfig, "ip": ShellSession._ip,
    "netstat": ShellSession._netstat, "free": ShellSession._free, "df": ShellSession._df,
    "uptime": ShellSession._uptime, "mount": ShellSession._mount, "date": ShellSession._date,
    "env": ShellSession._env, "set": ShellSession._env, "history": ShellSession._history,
    "reboot": ShellSession._reboot, "halt": ShellSession._reboot,
    "poweroff": ShellSession._reboot,
    "passwd": ShellSession._passwd,
    "iptables": ShellSession._denied, "insmod": ShellSession._denied,
    "mkfs": ShellSession._denied, "dd": ShellSession._denied,
    # Commands bots send blindly to escape vendor CLIs; a real shell ignores them.
    "enable": ShellSession._silent, "system": ShellSession._silent,
    "shell": ShellSession._silent, "linuxshell": ShellSession._silent,
    "export": ShellSession._silent, "unset": ShellSession._silent,
    "kill": ShellSession._silent, "killall": ShellSession._silent,
    "sleep": ShellSession._silent, "sync": ShellSession._silent,
    "true": ShellSession._silent, "clear": ShellSession._silent,
    "ulimit": ShellSession._silent, "umask": ShellSession._silent,
    "nohup": ShellSession._silent, "cd..": ShellSession._silent,
}
