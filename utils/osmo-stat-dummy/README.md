# Osmocom utilities

* osmo-stat-dummy: utility for rate counter and statsd testing

It has 2 rate counters: one ticks twice a seconds, another one can be manually updated with 'update-rate-ctr' command via vty.

The raw value is sent via statsd protocol. If you install "netdata" monitoring tool than you can open http://localhost:19999 in browser
and observe live counters monitoring under "StatsD dummy" without any additional setup.

Opening osmo-stat-dummy.html in browser while both netdata and osmo-stat-dummy are running will show dimensioned (per min/hour/day) rate counters as well as raw data.

The latter is handy for troubleshooting and comparing libosmocore's internal rate counter computation.
