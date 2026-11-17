# DNS Checker

A small desktop app in C, built with [CUI](https://github.com/yappologistic/CUI), that looks up a domain's DNS records and
builds DMARC records.

- **DNS-Einträge:** queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA of the domain through the
  zone's own name server (libresolv, on a worker thread), so changes show at once instead of
  after the cached TTL; without a reachable server it falls back to the system resolver. Also
  asks `www`, common DKIM selectors (Google, Microsoft 365, Mailchimp, SendGrid, `default`,
  and Hetzner's dated `default<YYMM>` when names exist below `_domainkey`) and the names typed
  under "Weitere Namen". DNS cannot list a zone's names, so other subdomains have to be named.
  Shows everything in a table filtered by type, names relative to the domain (`@`, `www`), and
  summarizes mail authentication (MX, SPF, DKIM, DMARC).
- **DMARC erstellen:** builds the `_dmarc` TXT record from policy, subdomain policy, percentage,
  report addresses and alignment, with copy buttons, hints for missing or external report
  addresses, and a comparison with the record the domain publishes today. After a lookup the
  form starts from the published record, so editing it cannot silently weaken the policy.
- **DMARC-Berichte:** takes the aggregate reports receivers mail to the rua address (`.zip`,
  `.gz` or `.xml`, dropped on the window or picked in a dialog), merges them per sender and
  shows how many messages passed SPF, DKIM and DMARC, failing senders first. Nothing leaves
  the machine.

## Build and run

Needs CMake, a C compiler, libxml2, zlib and libresolv (all ship with macOS). Tested on macOS.


```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release   # CUI: -DCUI_DIR=<checkout>, else fetched from GitHub
cmake --build build -j8
ctest --test-dir build --output-on-failure
./build/dns_checker                  # or: ./build/dns_checker example.com lp s1._domainkey
```

## Layout

| File | Job |
|---|---|
| `src/dns_lookup.c` | resolver queries, record data as text, domain input normalization |
| `src/domain_scan.c` | which names are asked, the queries, the mail authentication summary |
| `src/lookup_task.c` | the worker thread that runs a scan |
| `src/dmarc.c` | DMARC record builder and parser, report address checks |
| `src/report_file.c` | report files: zip, gzip or plain XML (zlib) |
| `src/dmarc_report.c` | aggregate report XML (libxml2), merging rows per sender |
| `src/main.c` | window, domain field, page switch |
| `src/page_records.c`, `src/page_dmarc.c`, `src/page_reports.c` | the three pages |
| `tests/test_core.c`, `tests/fixtures/` | tests for domain names, DMARC records and reports (no network) |
