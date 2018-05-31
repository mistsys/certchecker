package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/google/goterm/term"
	"github.com/mistsys/mist_go_utils/cloud"
	"github.com/mistsys/mist_go_utils/flag"
	"github.com/pkg/errors"
	scan "github.com/prasincs/ssllabs-scan"
	yaml "gopkg.in/yaml.v2"
)

const (
	errExpiringShortly = "%s: ** '%s' (S/N %X) expires in %d hours! **"
	errExpiringSoon    = "%s: '%s' (S/N %X) expires in roughly %d days."
	errSunsetAlg       = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
)

type CertCheckerResults struct {
	Host             string            `json:"Host"`
	TestTime         string            `json:"Time of Test"`
	ExpiryTime       string            `json:"Domain Expiry"`
	IPAddress        string            `json:"IP Address"`
	ServerName       string            `json:"Server Name"`
	Grade            string            `json:"Grade"`
	VulnerableTLS    string            `json:"Vulnerable TLS versions"`
	WeakCipherSuites string            `json:"Weak Cipher Suites TLSv1.2"`
	VulnResults      map[string]string `json:"Vulnerabilities"`
}

/* Future: Can integrate support for other API's
type SSLCheck interface {
	Scan(domain string) (*CertCheckerResults, error)
}

type SSLLabsChecker struct{}

func (s *SSLLabsChecker) Scan() (*CertCheckerResults, error){
	return nil, nil
}
*/

// MAP to label TLS versions as weak(false) or strong(true)
// Secure (low->high) SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, TLS v1.3
var versionsTLS = map[string]bool{
	"TLS:1.3": true,
	"TLS:1.2": true,
	"TLS:1.1": false,
	"TLS:1.0": false,
	"SSL:3.0": false,
	"SSL:2.0": false,
}

// readDomainsFile makes use of the file specified by input domainFile
// to create a map for domains specified
func readDomainsFile(domainFile string) (resp map[string][]string, err error) {
	yamlFile, err := ioutil.ReadFile(domainFile)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read %s", domainFile)
	}
	resp = make(map[string][]string)
	err = yaml.Unmarshal(yamlFile, resp)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse %s", domainFile)
	}
	return
}

// domainExpiry returns the expiry time for domain string
func domainExpiry(domain string) (time.Time, error) {
	// allow InsecureSkipVerify for only checking domains
	conn, err := tls.Dial("tcp", domain, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return time.Unix(0, 0), err
	}
	defer conn.Close()
	//checkedCerts := make(map[string]struct{})
	//certs := []string{}
	chains := conn.ConnectionState().PeerCertificates
	return chains[0].NotAfter, nil
}

// Method to Lookup IP from domain
func resolveIP(domain string) ([]string, error) {
	resolver := net.Resolver{}
	return resolver.LookupHost(context.Background(), domain)
}

// Method to Lookup CNAME from domain
func resolveCNAME(domain string) (string, error) {
	resolver := net.Resolver{}
	return resolver.LookupCNAME(context.Background(), domain)
}

// validate TLS checks for weak or insecure TLS versions
func validateTLS(details scan.LabsEndpointDetails) string {
	// Versions in increasing preference SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, TLS v1.3 (future)
	var versions string
	for _, protocolType := range details.Protocols {
		var vTLS = protocolType.Name + ":" + protocolType.Version
		if !versionsTLS[vTLS] {
			versions += vTLS + "\n"
		}
	}
	if versions != "" {
		return (versions)
	}
	return "No Vulnerable versions supported!"
}

// analyzeReasultValue makes use of switch-case statements to
// return outcome from various test results.
// Note: For new tests, add new switch-case here
func analyzeResultValue(test string, value int64) string {
	var testresult string
	switch test {
	case "Bleichenbacher":
		switch value {
		case -1:
			testresult = "test failed"
		case 0:
			testresult = "unknown"
		case 1:
			testresult = "not vulnerable"
		case 2:
			testresult = "vulnerable (weak oracle)"
		case 3:
			testresult = "vulnerable (strong oracle)"
		case 4:
			testresult = "inconsistent results"
		}
	case "ForwardSecrecy":
		switch value {
		case 1:
			testresult = "OK! Only one browser negotiated Forward Secrecy suite"
		case 2:
			testresult = "Good! server supports ECDHE suites, but not DHE"
		case 4:
			testresult = "Great! ECDHE + DHE combination supported"
		default:
			testresult = "Bad Result or Test Error"
		}
	case "OpenSslCcs":
		switch value {
		case -1:
			testresult = "test failed"
		case 0:
			testresult = "unknown"
		case 1:
			testresult = "not vulnerable"
		case 2:
			testresult = "possibly vulnerable, but not exploitable"
		case 3:
			testresult = "vulnerable and exploitable"
		}
	case "OpenSSLLuckyMinus20":
		switch value {
		case -1:
			testresult = "test failed"
		case 0:
			testresult = "unknown"
		case 1:
			testresult = "not vulnerable"
		case 2:
			testresult = "vulnerable and insecure"
		}
	case "Ticketbleed":
		switch value {
		case -1:
			testresult = "test failed"
		case 0:
			testresult = "unknown"
		case 1:
			testresult = "not vulnerable"
		case 2:
			testresult = "vulnerable and insecure"
		}
	case "PoodleTLS":
		switch value {
		case -3:
			testresult = "timeout"
		case -2:
			testresult = "TLS not supported"
		case -1:
			testresult = "test failed"
		case 0:
			testresult = "unknown"
		case 1:
			testresult = "not vulnerable"
		case 2:
			testresult = "vulnerable"
		}
	case "RenegSupport":
		if value > 1 {
			testresult = "secure"
		} else {
			testresult = "insecure client-initiated renegotiation is supported"
		}
	default:
		testresult = "Test Analysis not available!"

	}
	return testresult
}

// To colorize output for print-summary on CLI
func colorizeOutput(result string) string {
	var output string
	switch result {
	case "vulnerable":
		output = term.Redf(result)
	case "not vulnerable", "secure":
		output = term.Greenf(result)
	default:
		output = result
	}
	return output
}

// printCertCheckerResults function is called when print-summary flag is set
func printCertCheckerResults(scanResult *CertCheckerResults) {
	scanResults := reflect.ValueOf(scanResult).Elem()
	typeOfT := scanResults.Type()
	for i := 0; i < scanResults.NumField(); i++ {
		f := scanResults.Field(i)
		if f.Kind() == reflect.Map {
			for _, key := range f.MapKeys() {
				strct := f.MapIndex(key)
				fmt.Println(key.Interface(), ":", colorizeOutput(strct.Interface().(string)))
			}
		} else {
			fmt.Printf("%s: %v\n", typeOfT.Field(i).Name, f.Interface())
		}
	}
}

// prepare CSV to store data using struct certCheckerResults fields
func prepareCSV(scanResult *CertCheckerResults, fileName string) error {
	scanResults := reflect.ValueOf(scanResult).Elem()
	typeOfT := scanResults.Type()
	csvdatafile, err := os.Create(fileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", fileName)
	}
	defer csvdatafile.Close()
	writer := csv.NewWriter(csvdatafile)
	var record []string
	for i := 0; i < scanResults.NumField(); i++ {
		f := scanResults.Field(i)
		if f.Kind() == reflect.Map {
			var keys []string
			for key := range scanResult.VulnResults {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				record = append(record, key)
			}
		} else {
			record = append(record, typeOfT.Field(i).Name)
		}
	}
	writer.Write(record)
	writer.Flush()
	return err
}

// saveCertCheckerResults is called when save-summary flag is set
// It saves results in a CSV format in the file scan_data.csv
func saveCertCheckerResults(scanResult *CertCheckerResults, fileName string) error {
	scanResults := reflect.ValueOf(scanResult).Elem()
	csvdatafile, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to open file %s for write", fileName)
	}
	defer csvdatafile.Close()
	writer := csv.NewWriter(csvdatafile)

	var record []string

	for i := 0; i < scanResults.NumField(); i++ {
		f := scanResults.Field(i)
		if f.Kind() == reflect.Map {
			var keys []string
			for key := range scanResult.VulnResults {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				record = append(record, scanResult.VulnResults[key])
			}
		} else {
			record = append(record, f.Interface().(string))
		}
	}
	writer.Write(record)
	writer.Flush()
	return err
}

// weakCipherSuites lists all TLSv1.2 weak cipher suites supported
func weakCipherSuites(details scan.LabsEndpointDetails) string {
	//Will require update as more vulnerabilities discovered, display results for TLS v1.2
	//https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#23-use-secure-cipher-suites
	var vulnSuites string
	for _, suite := range details.Suites {
		for _, suiteList := range suite.List {
			if !strings.Contains(suiteList.Name, "DHE_") {
				if suite.Protocol == 771 {
					vulnSuites += suiteList.Name + "\n"
				}
			}
		}
	}
	return (vulnSuites)
}

// analyzeTestResults captures all tests specified in scanTests
// To add more test from SSL Labs API here, add to scanTests
func analyzeTestResults(details scan.LabsEndpointDetails) map[string]string {

	scanTests := []string{"VulnBeast", "RenegSupport", "ForwardSecrecy", "Heartbeat", "Heartbleed",
		"OpenSslCcs", "OpenSSLLuckyMinus20", "Ticketbleed", "Bleichenbacher",
		"Poodle", "PoodleTLS", "FallbackScsv", "Freak", "DhYsReuse", "Logjam",
		"DrownVulnerable", "SupportsRc4"}
	scanDetails := reflect.ValueOf(&details).Elem()
	vulnRslts := make(map[string]string)
	for _, test := range scanTests {
		testValue := scanDetails.FieldByName(test)
		valueType := testValue.Type().String()
		switch valueType {
		case "bool":
			if testValue.Bool() {
				vulnRslts[test] = "vulnerable"
			} else {
				vulnRslts[test] = "not vulnerable"
			}
		case "int":
			vulnRslts[test] = analyzeResultValue(test, testValue.Int())
		default:
			vulnRslts[test] = testValue.String()
		}
	}
	return vulnRslts
}

func main() {
	var domainsFile = flag.String("domains-file", "domains.yml", "List of domains separated by environments")
	var useCache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var showAllEndpoints = flag.Bool("all-endpoints", false, "If true, show all endpoints")
	var resolveIPFlag = flag.Bool("resolve-ip", false, "If true, resolves all the domain ips")
	var resolveCNAMEFlag = flag.Bool("resolve-cname", false, "If true resolve all the domain cname")
	var showExpiriesOnly = flag.Bool("expiries", false, "Only show expiries")
	var domains = flag.Strings("domain", []string{}, "Domains to scan for, overrides env")
	var saveSummary = flag.Bool("save-summary", false, "If true save results as summary")
	var fileName = flag.String("output", "scan-data.csv", "output file to store data")

	flag.Parse()
	envDomains, err := readDomainsFile(*domainsFile)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	if len(*domains) == 0 {
		envDomains := envDomains[cloud.ENV]
		domains = &envDomains
	}
	if *showExpiriesOnly {
		for _, domain := range *domains {
			expiresOn, err := domainExpiry(domain + ":443")
			if err != nil {
				log.Printf("Failed to get domain expiry for %s, Err: %s", domain, err)
			}
			if !*resolveIPFlag && !*resolveCNAMEFlag {
				fmt.Printf("%s => %s (%s)\n", domain, expiresOn, humanize.Time(expiresOn))
			} else if *resolveIPFlag {
				resolved, err := resolveIP(domain)
				if err != nil {
					log.Printf("Failed to lookup %s. Err: %s", domain, err)
				}
				fmt.Printf("%s: %s => %s (%s)\n", domain, strings.Join(resolved, ","), expiresOn, humanize.Time(expiresOn))
			} else if *resolveCNAMEFlag {
				resolved, err := resolveCNAME(domain)
				if err != nil {
					log.Printf("Failed to lookup %s. Err: %s", domain, err)
				}
				fmt.Printf("%s: %s => %s (%s)\n", domain, resolved, expiresOn, humanize.Time(expiresOn))
			}
		}
		return
	}

	log.Println("Preparing Summary..")
	log.Println("Checking domains: ", *domains)
	scan.IgnoreMismatch(true)
	scan.UseCache(*useCache)
	hp := scan.NewHostProvider(*domains)
	manager := scan.NewManager(hp)
	for {
		_, running := <-manager.FrontendEventChannel
		if !running {
			resultCount := 0
			if hp.StartingLen == 0 {
				return
			}
			summaryResult := make(map[string]CertCheckerResults)
			for _, report := range manager.Results.Reports {

				if len(report.Certs) == 0 {
					continue
				}
				for _, endpoint := range report.Endpoints {

					scanResult := new(CertCheckerResults)
					if endpoint.StatusMessage == "Ready" {
						scanResult.TestTime = time.Now().Format(time.RFC850)
					} else {
						scanResult.TestTime = "Endpoint Results not Available"
						log.Println("Endpoint Results not Available:", endpoint.StatusMessage)
						break
					}
					scanResult.Host = report.Host
					expiresOn := time.Unix(report.Certs[0].NotAfter/1000, 0)
					scanResult.ExpiryTime = humanize.Time(expiresOn)
					scanResult.Grade = endpoint.Grade
					scanResult.IPAddress = endpoint.IpAddress
					scanResult.ServerName = endpoint.ServerName
					details := endpoint.Details
					scanResult.VulnerableTLS = validateTLS(details)
					scanResult.WeakCipherSuites = weakCipherSuites(details)
					scanResult.VulnResults = analyzeTestResults(details)
					fmt.Printf("======== Results for %s =========\n", report.Host)
					printCertCheckerResults(scanResult)
					summaryResult[report.Host+"_"+endpoint.IpAddress] = *scanResult
					if !*showAllEndpoints {
						break
					}
				}

			}

			if *saveSummary {
				for _, savedResults := range summaryResult {
					if resultCount == 0 {
						err := prepareCSV(&savedResults, *fileName)
						if err != nil {
							log.Printf("Failed to create file %s. Err: %s", *fileName, err)
						}
					}
					err := saveCertCheckerResults(&savedResults, *fileName)
					if err != nil {
						log.Printf("Failed to write results for %s. Err: %s", savedResults.Host, err)
					}
					resultCount++
				}
				log.Println("Count of Results Saved: ", resultCount)
			}
			log.Println("Checking domains: ", *domains, "Done!")
			return
		}
	}

}
