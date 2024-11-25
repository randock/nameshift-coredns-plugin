// Package nameshift is a CoreDNS plugin that prints "nameshift" to stdout on every packet received.
// It serves as an nameshift CoreDNS plugin with numerous code comments.
package nameshift

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("nameshift")

// Nameshift is an nameshift plugin to show how to write a plugin.
type Nameshift struct {
	Next plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nameshift is used
// in a Server.
func (e *Nameshift) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if e.handleDns(w, r) {
		// Export metric with the server label set to the current server handling the request.
		requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

		return dns.RcodeSuccess, nil
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
}

func (e *Nameshift) handleDns(w dns.ResponseWriter, r *dns.Msg) bool {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	qtype := state.Type()

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Debug(qname)

	var rrs []dns.RR
	var authoritive []dns.RR

	authoritive = append(authoritive, &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(qname),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns: "ns1.nameshift.com",
	})

	authoritive = append(authoritive, &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(qname),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns: "ns2.nameshift.com",
	})

	switch qtype {
	case "A":
		rrs = append(rrs, &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qname),
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("123.123.123.123"),
		})
	case "AAAA":
		rrs = append(rrs, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qname),
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			AAAA: net.ParseIP("2a09:8280:1::50:73de:0"),
		})
	default:
		return false
	}

	log.Debug("Sending reply")

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = rrs
	m.Ns = authoritive
	w.WriteMsg(m)

	return true

}

// Name implements the Handler interface.
func (e *Nameshift) Name() string { return "nameshift" }
