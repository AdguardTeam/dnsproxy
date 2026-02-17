package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := "127.0.0.1:53536"
	domains := []string{"google.com.", "example.com.", "cloudflare.com.", "microsoft.com."}

	c := new(dns.Client)
	c.Net = "udp"

	for i := 0; i < 60; i++ {
		fmt.Printf("Round %d\n", i)
		for _, domain := range domains {
			m := new(dns.Msg)
			m.SetQuestion(domain, dns.TypeA)
			r, _, err := c.Exchange(m, server)
			if err != nil {
				fmt.Printf("Error querying %s: %v\n", domain, err)
				continue
			}
			if len(r.Answer) > 0 {
				fmt.Printf("Got answer for %s: TTL %d\n", domain, r.Answer[0].Header().Ttl)
			} else {
				fmt.Printf("No answer for %s\n", domain)
			}
		}
		time.Sleep(2 * time.Second)
	}
}
