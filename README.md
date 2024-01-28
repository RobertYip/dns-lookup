# DNS Lookup with cache
A Java implementation of DNS lookup with cache usage.

## Setup
1. Clone directory
2. In root folder, compile code with `javac -d out src/ca/ubc/cs/cs317/dnslookup/*.java`
3. Create jar file `jar cfe dnslookup.jar ca.ubc.cs.cs317.dnslookup.DNSLookupCUI -C out .
   `
4. Run jar file `java -jar dnslookup.jar`

## How to use
Description is listed directly in terminal, but here is a reference.

Commands:

| Command          | Example           | Description                       |
|------------------|-------------------|-----------------------------------|
| lookup <url>     | lookup github.com | Returns dns information of url    |
| verbose <on/off> | verbose on        | Shows all steps of the dns tracing |
| dump             | dump              | dumps all resources used          |
| reset            | reset             | resets cache and program          |
| quit             | quit              | exits program                     | 

## Example
With verbose on:
`lookup google.com`
```agsl
Query ID     41388 google.com  A --> 192.33.14.30
Response ID: 41388 Authoritative = false Error = 0 (No error)
  Answers (0)
  Nameservers (4)
       google.com                     172800     NS    IN    ns2.google.com
       google.com                     172800     NS    IN    ns1.google.com
       google.com                     172800     NS    IN    ns3.google.com
       google.com                     172800     NS    IN    ns4.google.com
  Additional Information (8)
       ns2.google.com                 172800     AAAA  IN    2001:4860:4802:34:0:0:0:a
       ns2.google.com                 172800     A     IN    216.239.34.10
       ns1.google.com                 172800     AAAA  IN    2001:4860:4802:32:0:0:0:a
       ns1.google.com                 172800     A     IN    216.239.32.10
       ns3.google.com                 172800     AAAA  IN    2001:4860:4802:36:0:0:0:a
       ns3.google.com                 172800     A     IN    216.239.36.10
       ns4.google.com                 172800     AAAA  IN    2001:4860:4802:38:0:0:0:a
       ns4.google.com                 172800     A     IN    216.239.38.10


Query ID     59076 google.com  A --> 216.239.38.10
Response ID: 59076 Authoritative = true Error = 0 (No error)
  Answers (1)
       google.com                     300        A     IN    142.251.41.78
  Nameservers (0)
  Additional Information (0)

========== FINAL RESULT ==========
       google.com                     300        A     IN    142.251.41.78
```