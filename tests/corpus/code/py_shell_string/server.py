import subprocess


def convert(name: str) -> None:
    subprocess.run(f"convert {name} out.png", shell=True, check=True)
