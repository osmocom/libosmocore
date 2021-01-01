#!/usr/bin/env python3

# (C) 2021 by sysmocom - s.f.m.c. GmbH
# Author: Alexander Couzens <lynxis@fe80.eu>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

app_configs = {
    "osmo-ns-dummy": ["osmo-ns-dummy.cfg"],
}

apps = [(45999, "../../utils/osmo-ns-dummy -p 45999", "OsmoNSdummy", "osmo-ns-dummy")
        ]

vty_command = ["../../utils/osmo-ns-dummy", "-p", "45999", "-c", "osmo-ns-dummy.cfg"]

vty_app = apps[0]
