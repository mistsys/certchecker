CertChecker
=============
> CLI tool to check certificate security health and score against SSLlabs' scanner.

With many services now being offered with setups across envirnments and using a combination of micro-services exposed via domains it is imperative to perform periodical checks of each domain. CertChecker provides a quick analysis both as a CLI tool or to generate periodic reports on domain expiries and security vulnerabilities.

The tool utilizes API calls to SSL Labs, a brief report on domain "www.google.com" is available at 
https://www.ssllabs.com/ssltest/analyze.html?d=www.google.com

## Requirements

* Go >= 1.3

## Installation

To Download and Install the package and its dependencies, use the following commands::

```
go get github.com/mistsys/certchecker
cd $GOPATH/src/github.com/mistsys/certchecker
go get -u -d ./...
```

## Usage

SYNOPSIS

```
    go run certchecker.go --env <environment> [options]
```


The tool can be used with the following options:

- **usecache**: this flag can be used to retrieve results from the cached results of the service is available
- **save-summary**: To save the summary of scans in a CSV format, use save-summary flag
- **expiries**: For a quick view of expiries of domain, use the expiries flag
- **all-endpoints**: scans for vulnerabilities across all the endpoints for domains specified
- **environment**: run scans for different environments specified in YAML file
- **output** <filename>: Use this flag to specify the output file to save data when save-summary option is used, default is scan-data.csv

The result contains scans 
- Domain Expiry Time
- Grade (Overall grade provided by SSLLabs)
- Vulnerable TLS versions supported
- Weak Cipher Suites supported
- Status on other Vulnerabilities (more types of checks can be added to the code as a list)

This tool can be used for reporting purposes by configuring a schedule run as required. 

## Example

To get a scan on vulnerabilities:

`$ go run certchecker.go --env google --usecache`


Output:

```
2018/07/03 14:18:44 Preparing Summary..
2018/07/03 14:18:44 Checking domains:  [google.com]
2018/07/03 14:18:44 [NOTICE] Server message:
This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html
======== Results for google.com =========
Host: google.com
TestTime: Tuesday, 03-Jul-18 14:18:47 PDT
ExpiryTime: 1 month from now
IPAddress: 2607:f8b0:4005:802:0:0:0:200e
ServerName: sfo07s26-in-x0e.1e100.net
Grade: A
VulnerableTLS: TLS:1.0
TLS:1.1

WeakCipherSuites: TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA

SupportsRc4 : not vulnerable
OpenSslCcs : not vulnerable
Bleichenbacher : not vulnerable
PoodleTLS : not vulnerable
ForwardSecrecy : Good! server supports ECDHE suites, but not DHE
Heartbeat : not vulnerable
FallbackScsv : vulnerable
DhYsReuse : not vulnerable
DrownVulnerable : not vulnerable
RenegSupport : secure
Heartbleed : not vulnerable
Ticketbleed : not vulnerable
Freak : not vulnerable
Logjam : not vulnerable
VulnBeast : vulnerable
OpenSSLLuckyMinus20 : not vulnerable
Poodle : not vulnerable
2018/07/03 14:18:47 Checking domains:  [google.com] Done!
```

To check for expiries for domains in an environment:

`$go run certchecker.go --env google --expiries`

Output:

```shell
google.com => 2018-08-28 11:32:00 +0000 UTC (1 month from now)
```

## Note

To add more features to the tool or to understand how results are analysed visit :
[SSL Labs API ](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md "SSL Labs API ")

## Authors

- Sumit Bajaj
- Prasanna Gautam




