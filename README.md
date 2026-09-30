# Shadow-Traffic
watches real outbound TCP connections for a fixed window (default 2 minutes), reads the destination hostname straight off the wire when it can (via the TLS ClientHello's SNI field, using a hand-written low-level packet parser — no external capture tool required beyond Windows' own pktmon)
