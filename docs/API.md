# API guide

Native target: `AdvancedNetwork`. See `SDK/` and executable examples/tests for exact signatures. Live operations require the matching driver; offline validators do not install or load it.

WFP IPv4/IPv6 connection metadata and ordered allow/block rules by canonical executable app ID, protocol, remote CIDR, direction and port. Policies have at most 64 rules. `RuleForApplication` resolves the executable through the official WFP app-ID API.

Keep the RAII session alive while observing or enforcing rules. Stop explicitly before changing owners; destruction closes the owner handle. Read status and loss counters during polling. Do not react automatically to incomplete evidence.
