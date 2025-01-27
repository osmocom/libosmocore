#!/usr/bin/env python3
# Copyright 2025 sysmocom - s.f.m.c. GmbH
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse
import copy
import fnmatch
import os
import shutil
import string
import subprocess
import sys

args = None


def parse_arguments():
    global args

    parser = argparse.ArgumentParser(
        description="Install debug packages for all installed Osmocom packages and dependencies"
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="run non-interactively",
    )
    args = parser.parse_args()


def check_package_manager():
    rel = "/etc/os-release"

    if not os.path.exists(rel):
        print(f"ERROR: {rel} does not exist")
        sys.exit(1)

    with open(rel) as f:
        for line in f:
            if "ID=debian" in line or "ID_LIKE=debian" in line:
                return

    print("ERROR: only 'apt' is supported by this script")
    sys.exit(1)


def check_requirements():
    if not shutil.which("apt-rdepends"):
        print("ERROR: please install apt-rdepends first:")
        print("  apt install apt-rdepends")
        sys.exit(1)


def get_installed_osmocom_packages():
    """Get installed Osmocom packages by parsing 'dpkg -l' output. Lines with
    installed packages look like this: 'ii  libosmocore22:amd64 ...'"""
    ret = set()
    p = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, check=True)
    lines = p.stdout.split("\n")

    patterns = [
        "gapk*",
        "libasn1c*",
        "libgtpnl*",
        "libosmo*",
        "libsmpp34*",
        "osmo-*",
    ]

    for line in lines:
        if not line.startswith("ii  "):
            continue
        package = line.split(" ", 4)[2].split(":", 1)[0]
        for pattern in patterns:
            if fnmatch.fnmatch(package, pattern):
                ret.add(package)
                break

    return ret


def get_recursive_dependencies(pkgs):
    """Iterate over apt-rdepends output, it looks like:
    osmo-mgw
      Depends: libc6 (>= 2.34)
      Depends: libosmoabis13"""
    ret = copy.copy(pkgs)

    p = subprocess.run(["apt-rdepends"] + list(pkgs), capture_output=True, text=True, check=True)
    lines = p.stdout.split("\n")
    for line in lines:
        if not line.startswith("  Depends: "):
            continue
        ret.add(line.strip().split(" ", 3)[1])

    return ret


def get_debug_pkgs():
    p = subprocess.run("apt-cache pkgnames | grep -- -dbg", shell=True, text=True, capture_output=True)
    return p.stdout.split("\n")


def get_debug_pkgs_relevant(debug_pkgs, pkgs_with_deps):
    ret = []
    for pkg in pkgs_with_deps:
        names = [f"{pkg}-dbg", f"{pkg}-dbgsym"]

        pkg_nodigits = pkg.rstrip(string.digits)
        if pkg != pkg_nodigits:
            names += [f"{pkg_nodigits}-dbg", f"{pkg_nodigits}-dbgsym"]

        for name in names:
            if name in debug_pkgs:
                ret += [name]
                break

    return ret


def install_packages(pkgs):
    cmd = []
    if os.geteuid() != 0:
        cmd += ["sudo"]
    cmd += ["apt", "install"]
    if args.yes:
        cmd += ["-y"]
    cmd += pkgs

    print(f"+ {cmd}")
    p = subprocess.run(cmd)
    sys.exit(p.returncode)


def main():
    parse_arguments()
    check_package_manager()
    check_requirements()

    print("Getting installed Osmocom packages...")
    pkgs = get_installed_osmocom_packages()
    print("Getting dependencies of installed Osmocom packages...")
    pkgs_with_deps = get_recursive_dependencies(pkgs)
    print("Getting available debug packages...")
    debug_pkgs = get_debug_pkgs()
    print("Getting relevant debug packages...")
    debug_pkgs_relevant = get_debug_pkgs_relevant(debug_pkgs, pkgs_with_deps)
    debug_pkgs_relevant = sorted(list(debug_pkgs_relevant))

    print("Running apt install...")
    install_packages(debug_pkgs_relevant)


if __name__ == "__main__":
    main()
