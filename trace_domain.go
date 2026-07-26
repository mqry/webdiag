package main

import (
	"net"
	"strings"
)

func traceDomain(domain string) []string {
	var chain []string
	current := domain

	for i := 0; i < 10; i++ {
		if ip := net.ParseIP(current); ip != nil {
			chain = append(chain, current)
			break
		}

		cname, err := net.LookupCNAME(current)
		if err != nil {
			break
		}

		cname = strings.TrimSuffix(cname, ".")

		if cname == current {
			if ips, err := net.LookupIP(cname); err == nil && len(ips) > 0 {
				chain = append(chain, ips[0].String())
			}
			break
		}

		chain = append(chain, cname)
		current = cname
	}

	return chain
}
