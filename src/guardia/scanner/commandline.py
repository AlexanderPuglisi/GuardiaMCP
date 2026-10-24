from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".com")
OFFICIAL_REGISTRIES: dict[str, frozenset[str]] = {
    "npm": frozenset({"registry.npmjs.org", "registry.yarnpkg.com"}),
    "pypi": frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"}),
}

NPM_RUNNERS: dict[tuple[str, ...], str] = {
    ("npx",): "npm",
    ("bunx",): "npm",
    ("pnpx",): "npm",
    ("pnpm", "dlx"): "npm",
    ("yarn", "dlx"): "npm",
    ("npm", "exec"): "npm",
    ("npm", "x"): "npm",
    ("bun", "x"): "npm",
    ("uvx",): "pypi",
    ("uv", "tool", "run"): "pypi",
    ("pipx", "run"): "pypi",
}

NPM_PACKAGE_FLAGS = frozenset({"-p", "--package"})
NPM_VALUE_FLAGS = frozenset(
    {"--registry", "--cache", "--userconfig", "-c", "--call", "-w", "--workspace"}
)
NPM_REGISTRY_FLAGS = frozenset({"--registry"})
PYPI_PACKAGE_FLAGS = frozenset({"--from", "--spec"})
PYPI_VALUE_FLAGS = frozenset(
    {
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--constraints",
        "--overrides",
        "--pip-args",
        "--index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--default-index",
        "--find-links",
        "-f",
    }
)
PYPI_REGISTRY_FLAGS = frozenset(
    {"--index", "--index-url", "-i", "--extra-index-url", "--default-index", "--find-links", "-f"}
)

REMOTE_SPEC = re.compile(
    r"^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?://|ftp://|file:)", re.IGNORECASE
)
GITHUB_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$")
LOCAL_SPEC = re.compile(r"^(\.{1,2}([\\/]|$)|[\\/]|[A-Za-z]:[\\/]|~)")
NPM_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$")
PYPI_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?"
    r"(?:\s*(?P<op>===|==|@|>=|<=|~=|!=|>|<)\s*(?P<version>\S+))?$"
)
PYPI_EXACT_VERSION = re.compile(r"^\d+(\.\d+)*([a-z0-9.+-]*)$", re.IGNORECASE)


def program_name(command: str) -> str:
    name = re.split(r"[\\/]", command.strip().strip('"'))[-1].lower()
    for suffix in EXECUTABLE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def package_key(ecosystem: str, name: str) -> str:
    lowered = name.strip().lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem == "pypi" else lowered


def official_registry(ecosystem: str, url: str) -> bool:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and host in OFFICIAL_REGISTRIES.get(ecosystem, ())


@dataclass(frozen=True, slots=True)
class PackageRef:
    ecosystem: str
    spec: str
    name: str
    version: str | None
    arg_index: int
    pinned: bool
    remote: bool


@dataclass(frozen=True, slots=True)
class RunnerCall:
    ecosystem: str
    packages: tuple[PackageRef, ...]
    registries: tuple[tuple[int, str], ...]


def _match_runner(command: str, args: Sequence[str]) -> tuple[str, int] | None:
    tokens = [program_name(command), *(a.lower() for a in args[:2])]
    for prefix, ecosystem in NPM_RUNNERS.items():
        if tuple(tokens[: len(prefix)]) == prefix:
            return ecosystem, len(prefix) - 1
    return None


def split_npm_spec(spec: str) -> tuple[str, str | None]:
    at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    if at <= 0:
        return spec, None
    return spec[:at], spec[at + 1 :]


def npm_package(spec: str, index: int) -> PackageRef | None:
    if LOCAL_SPEC.match(spec):
        return None
    if REMOTE_SPEC.match(spec) or (not spec.startswith("@") and GITHUB_SHORTHAND.match(spec)):
        return PackageRef("npm", spec, spec, None, index, pinned=False, remote=True)
    name, version = split_npm_spec(spec)
    pinned = version is not None and NPM_EXACT_VERSION.match(version) is not None
    return PackageRef("npm", spec, name, version, index, pinned=pinned, remote=False)


def pypi_package(spec: str, index: int) -> PackageRef | None:
    if LOCAL_SPEC.match(spec):
        return None
    if REMOTE_SPEC.match(spec) or " @ " in spec:
        return PackageRef("pypi", spec, spec, None, index, pinned=False, remote=True)
    match = PYPI_SPEC.match(spec)
    if match is None:
        return PackageRef("pypi", spec, spec, None, index, pinned=False, remote=False)
    version = match["version"]
    pinned = (
        match["op"] in ("==", "===", "@")
        and version is not None
        and PYPI_EXACT_VERSION.match(version) is not None
        and version.lower() != "latest"
    )
    return PackageRef("pypi", spec, match["name"], version, index, pinned=pinned, remote=False)


def _flag_value(arg: str, flags: frozenset[str]) -> str | None:
    name, eq, value = arg.partition("=")
    if eq and name.lower() in flags:
        return value
    return None


def parse_runner(command: str | None, args: Sequence[str]) -> RunnerCall | None:
    if command is None:
        return None
    matched = _match_runner(command, args)
    if matched is None:
        return None
    ecosystem, first = matched
    package_flags = NPM_PACKAGE_FLAGS if ecosystem == "npm" else PYPI_PACKAGE_FLAGS
    value_flags = NPM_VALUE_FLAGS if ecosystem == "npm" else PYPI_VALUE_FLAGS
    registry_flags = NPM_REGISTRY_FLAGS if ecosystem == "npm" else PYPI_REGISTRY_FLAGS
    build = npm_package if ecosystem == "npm" else pypi_package
    specs: list[tuple[int, str]] = []
    registries: list[tuple[int, str]] = []
    index = first
    positional: tuple[int, str] | None = None
    while index < len(args):
        arg = args[index]
        lowered = arg.lower()
        if lowered in package_flags and index + 1 < len(args):
            specs.append((index + 1, args[index + 1]))
            index += 2
            continue
        inline_package = _flag_value(arg, package_flags)
        if inline_package is not None:
            specs.append((index, inline_package))
            index += 1
            continue
        inline_registry = _flag_value(arg, registry_flags)
        if inline_registry is not None:
            registries.append((index, inline_registry))
            index += 1
            continue
        if lowered in value_flags and index + 1 < len(args):
            if lowered in registry_flags:
                registries.append((index + 1, args[index + 1]))
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        positional = (index, arg)
        break
    if not specs and positional is not None:
        specs.append(positional)
    packages = tuple(p for i, s in specs if (p := build(s, i)) is not None)
    return RunnerCall(ecosystem, packages, tuple(registries))


DOCKER_VALUE_FLAGS = frozenset(
    {
        "-a",
        "--attach",
        "--add-host",
        "--annotation",
        "--arch",
        "--blkio-weight",
        "--blkio-weight-device",
        "-c",
        "--cpu-shares",
        "--cap-add",
        "--cap-drop",
        "--cgroup-conf",
        "--cgroup-parent",
        "--cgroupns",
        "--cgroups",
        "--chrootdirs",
        "--cidfile",
        "--conmon-pidfile",
        "--cpu-count",
        "--cpu-percent",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--decryption-key",
        "--detach-keys",
        "--device",
        "--device-cgroup-rule",
        "--device-read-bps",
        "--device-read-iops",
        "--device-write-bps",
        "--device-write-iops",
        "--dns",
        "--dns-opt",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "--entrypoint",
        "-e",
        "--env",
        "--env-file",
        "--env-merge",
        "--expose",
        "--gidmap",
        "--gpus",
        "--group-add",
        "--group-entry",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-interval",
        "--health-start-period",
        "--health-timeout",
        "-h",
        "--hostname",
        "--hooks-dir",
        "--hostuser",
        "--image-volume",
        "--init-path",
        "--io-maxbandwidth",
        "--io-maxiops",
        "--ip",
        "--ip6",
        "--ipc",
        "--isolation",
        "--kernel-memory",
        "-l",
        "--label",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--log-driver",
        "--log-opt",
        "-m",
        "--memory",
        "--mac-address",
        "--memory-reservation",
        "--memory-swap",
        "--memory-swappiness",
        "--mount",
        "--name",
        "--net",
        "--net-alias",
        "--network",
        "--network-alias",
        "--oom-score-adj",
        "--os",
        "-p",
        "--publish",
        "--passwd-entry",
        "--personality",
        "--pid",
        "--pidfile",
        "--pids-limit",
        "--platform",
        "--pod",
        "--pod-id-file",
        "--preserve-fds",
        "--pull",
        "--rdt-class",
        "--requires",
        "--restart",
        "--retry",
        "--retry-delay",
        "--runtime",
        "--sdnotify",
        "--seccomp-policy",
        "--secret",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--subgidname",
        "--subuidname",
        "--sysctl",
        "--timeout",
        "--tmpfs",
        "--tz",
        "-u",
        "--user",
        "--uidmap",
        "--ulimit",
        "--umask",
        "--userns",
        "--uts",
        "-v",
        "--volume",
        "--variant",
        "--volume-driver",
        "--volumes-from",
        "-w",
        "--workdir",
    }
)


@dataclass(frozen=True, slots=True)
class DockerRun:
    image: tuple[int, str] | None
    options: tuple[tuple[int, str, str], ...]


def parse_docker_run(command: str | None, args: Sequence[str]) -> DockerRun | None:
    if command is None or program_name(command) not in ("docker", "podman", "nerdctl"):
        return None
    if not args or args[0].lower() not in ("run", "create"):
        return None
    options: list[tuple[int, str, str]] = []
    index = 1
    while index < len(args):
        arg = args[index]
        name, eq, value = arg.partition("=")
        lowered = name.lower()
        if arg.startswith("-") and eq:
            options.append((index, lowered, value))
            index += 1
        elif lowered in DOCKER_VALUE_FLAGS and index + 1 < len(args):
            options.append((index + 1, lowered, args[index + 1]))
            index += 2
        elif arg.startswith("-"):
            options.append((index, lowered, ""))
            index += 1
        else:
            return DockerRun((index, arg), tuple(options))
    return DockerRun(None, tuple(options))


def damerau_levenshtein(first: str, second: str, limit: int = 3) -> int:
    if abs(len(first) - len(second)) > limit:
        return limit + 1
    previous_previous: list[int] = []
    previous = list(range(len(second) + 1))
    for i in range(1, len(first) + 1):
        current = [i] + [0] * len(second)
        for j in range(1, len(second) + 1):
            cost = 0 if first[i - 1] == second[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and first[i - 1] == second[j - 2] and first[i - 2] == second[j - 1]:
                current[j] = min(current[j], previous_previous[j - 2] + 1)
        previous_previous, previous = previous, current
    return previous[len(second)]
