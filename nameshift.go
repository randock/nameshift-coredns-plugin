// Package nameshift is a CoreDNS plugin that prints "nameshift" to stdout on every packet received.
// It serves as an nameshift CoreDNS plugin with numerous code comments.
package nameshift

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/publicsuffix"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("nameshift")
var mutex sync.RWMutex = sync.RWMutex{}

const (
	TTL = 900
)

var serial uint32

type RedisRecord struct {
	SidnIdcode *string `json:"sidnIdcode"`
	Identifier string  `json:"identifier"`
	A          string  `json:"a"`
	Aaaa       *string `json:"aaaa"`
}

// Nameshift is an nameshift plugin to show how to write a plugin.
type Nameshift struct {
	Next   plugin.Handler
	Client *redis.Client

	Prefix      string
	AddNs3      bool
	Nameservers []string

	zone map[string]RedisRecord
}

func (e Nameshift) loadRecord(ctx context.Context, domain string) (*RedisRecord, error) {
	mutex.Lock()
	defer mutex.Unlock()

	val := e.Client.Get(ctx, "identifier/"+domain)
	if val.Err() != nil {
		log.Error(fmt.Errorf("unable to get record for %s: %v", domain, val.Err()))
		return nil, val.Err()
	}

	record := &RedisRecord{}
	if err := json.Unmarshal([]byte(val.Val()), record); err != nil {
		log.Error(fmt.Errorf("unable to unmarshal value for %s: %v", domain, err))
		return nil, err
	}

	return record, nil
}

// ServeDNS implements the plugin.Handler interface. This method gets called when nameshift is used
// in a Server.
func (e Nameshift) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if e.handleDns(ctx, w, r) {
		// Export metric with the server label set to the current server handling the request.
		requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

		return dns.RcodeSuccess, nil
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
}

func NewCAA(fqdn string, flag uint8, tag string, value string) dns.RR {
	return &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		Flag:  flag,
		Tag:   tag,
		Value: value,
	}
}

func newNS(fqdn string, authority string) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		Ns: authority,
	}
}

func newA(fqdn string, a string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		A: net.ParseIP(a),
	}
}

func newAAAA(fqdn string, aaaa string) dns.RR {
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		AAAA: net.ParseIP(aaaa),
	}
}

func newTXT(fqdn string, txt []string) dns.RR {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		Txt: txt,
	}
}

func newSOA(mainNs string, fqdn string, serial uint32) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		},
		Ns:      mainNs,
		Mbox:    "hostmaster.nameshift.com.",
		Refresh: 60 * 60,
		Retry:   uint32(math.Round(60 * 60 * 1 * 1 / 3)),
		Expire:  60 * 60 * 24 * 7,
		Minttl:  60 * 60 * 1,
		Serial:  uint32(time.Now().Unix()),
	}
}

func (e Nameshift) handleDns(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) bool {
	state := request.Request{W: w, Req: r}
	qtype := state.Type()
	fqdn := dns.Fqdn(state.Name())

	root, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(state.Name(), "."))
	if err != nil {
		log.Error(fmt.Errorf("could not get root name %s %v", state.Name(), err))
		return false
	}

	// sub
	sub := strings.TrimSuffix(strings.TrimSuffix(state.Name(), root+"."), ".")

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Debug(fmt.Sprintf("Grabbing DNS for %s, root domain: %s, sub domain: %s", state.Name(), root, sub))

	// lookup record in map
	val, err := e.loadRecord(ctx, root)
	if err != nil {
		log.Error(fmt.Errorf("could not get record for %s: %v", root, err))
		return false
	}

	redisRecordFound := val != nil

	// create rrs
	var rrs []dns.RR
	var authoritive []dns.RR

	for _, value := range e.Nameservers {
		authoritive = append(
			authoritive,
			newNS(fqdn, value),
		)
	}

	if e.AddNs3 && redisRecordFound {
		authoritive = append(authoritive, newNS(fqdn, val.Identifier+".ns3.nameshift.com."))
	}

	switch qtype {
	case "TXT":
		if sub == "_for-sale" && val.SidnIdcode != nil {
			rrs = append(rrs, newTXT(fqdn, []string{"idcode=" + *val.SidnIdcode}))
		}
	case "SOA":
		rrs = append(rrs, newSOA(e.Nameservers[0], fqdn, serial))
	case "NS":
		rrs = append(rrs, authoritive...)
	case "CAA":
		rrs = append(
			rrs,
			NewCAA(fqdn, 0, "issue", "letsencrypt.org"),
			NewCAA(fqdn, 0, "issue", "pki.goog"),
		)
	case "A":
		if sub == "www" || sub == "" {
			if redisRecordFound {
				rrs = append(rrs, newA(fqdn, val.A))
			} else {
				rrs = append(rrs, newA(fqdn, "168.220.85.117"))
			}
		}
	case "AAAA":
		if sub == "www" || sub == "" {
			if redisRecordFound {
				if val.Aaaa != nil {
					rrs = append(rrs, newAAAA(fqdn, *val.Aaaa))
				}
			} else {
				rrs = append(rrs, newAAAA(fqdn, "2a09:8280:1::50:73de:0"))
			}
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = rrs
	m.Ns = authoritive

	w.WriteMsg(m)

	return true
}

// Name implements the Handler interface.
func (e Nameshift) Name() string { return "nameshift" }
