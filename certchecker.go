package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/google/goterm/term"
	"github.com/mistsys/mist_go_utils/cloud"
	"github.com/mistsys/mist_go_utils/flag"
	"github.com/pkg/errors"
	scan "github.com/prasincs/ssllabs-scan"
	yaml "gopkg.in/yaml.v2"
)

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

func checkAllTrue(items ...bool) string {
	for i, item := range items {
		if !item {
			return term.Redf("Error on %d", i)
		}
	}
	return term.Green("OK").String()
}

func checkAllFalse(items ...bool) string {
	for i, item := range items {
		if item {
			return term.Redf("Error on %d", i)
		}
	}
	return term.Green("OK").String()
}

func main() {
	var domainsFile = flag.String("domains-file", "domains.yml", "List of domains separated by environments")
	var useCache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var showAllEndpoints = flag.Bool("all-endpoints", false, "If true, show all endpoints")
	var showExpiriesOnly = flag.Bool("expiries", false, "Only show expiries")
	flag.Parse()
	envDomains, err := readDomainsFile(*domainsFile)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	domains := envDomains[cloud.ENV]
	log.Println(domains)
	scan.IgnoreMismatch(true)
	scan.UseCache(*useCache)
	hp := scan.NewHostProvider(domains)
	manager := scan.NewManager(hp)
	for {
		_, running := <-manager.FrontendEventChannel
		if !running {
			if hp.StartingLen == 0 {
				return
			}
			for _, report := range manager.Results.Reports {
				fmt.Println(report.Host)

				//fmt.Printf("%#v\n", report)
				if len(report.Certs) == 0 {
					continue
				}
				expiresOn := time.Unix(report.Certs[0].NotAfter/1000, 0)
				fmt.Printf("ExpiryTime: %s(%s)\n", expiresOn, humanize.Time(expiresOn))
				if *showExpiriesOnly {
					continue
				}
				for _, endpoint := range report.Endpoints {

					fmt.Printf("Grade: %s\n", endpoint.Grade)
					details := endpoint.Details

					fmt.Println("==== Vulnerabilities ===")
					//fmt.Printf("vulnerable TLS versions supported: %s\n", checkAllTrue(validateTLS(details)))
					fmt.Printf("RC4 is Not Supported: %s\n", checkAllFalse(details.Rc4Only, details.SupportsRc4))
					fmt.Printf("Heartbeat: %s\n", checkAllFalse(details.Heartbeat))
					fmt.Printf("Heartbleed: %s\n", checkAllFalse(details.Heartbleed))
					fmt.Printf("Poodle: %s\n", checkAllFalse(details.Poodle))
					fmt.Printf("DH public server params reuse: %s\n", checkAllFalse(details.DhYsReuse))
					//fmt.Printf("DH public server params reuse: %s\n", checkAllFalse(details.ECDHE))
					fmt.Printf("Downgrade Attack Prevention: %s\n", checkAllFalse)
					fmt.Printf("Logjam: %s\n", checkAllFalse(details.Logjam))
					fmt.Printf("Drown: %s\n", checkAllFalse(details.DrownVulnerable))
					fmt.Printf("BEAST: %s\n", checkAllFalse(details.VulnBeast))
					//fmt.Println("==== Cipher Suites ===")

					//for _, suite := range details.Suites {

					//}
					//fmt.Printf("%#v\n", details.Suites)
					fmt.Println()
					if !*showAllEndpoints {
						break
					}
				}

				//fmt.Printf("%v\n", report.)
			}
			return
		}
	}
}
