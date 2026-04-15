IpRanger is a TCP traffic monitoring and blocking tool for Debian / Ubuntu servers

## Goal

Give insights into the TCP traffic flowing to your server to automatically block traffic from unwanted and malicious sources.
Reduce the amount of problematic bot traffic and automatically stop scrapers overwhelming the server.
Remove the need to manually look up IP ranges and hand edit iptable rules and ipsets.

## Features

- Monitor open(ed) TCP connections
- Create statistics about the visited IPs
- Group IPs into IP ranges based on RDAP look ups
- Fetch IPs and IP ranges from ip block lists
- Fetch bad ASN and ASN prefixes from block lists
- Auto update of the block lists
- Flush & restore ipset for iptable
- Built on top of iptable and ipset
- Configuration for friendly IPs and IP ranges
- Modern web UI
  - Display the statistics about the visited IPs with grouping
  - Display the blocked IPs and IP ranges
  - Display bad IPs and IP ranges
- (optional) Allow per country blocking
