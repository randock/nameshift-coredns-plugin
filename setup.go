package nameshift

import (
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	redis "github.com/redis/go-redis/v9"
)

const (
	DefaultRedisAddress  = "127.0.0.1:6379"
	DefaultRedisUsername = "default"
	DefaultTTL           = uint32(900)
)

// init registers this plugin.
func init() { plugin.Register("nameshift", setup) }

// setup is the function that gets called when the config parser see the token "nameshift". Setup is responsible
// for parsing any extra options the nameshift plugin may have. The first token this function sees is "nameshift".
func setup(d *caddy.Controller) error {

	address := DefaultRedisAddress
	username := DefaultRedisUsername
	password := ""
	prefix := ""
	ns3 := false
	ns := []string{}
	ttl := DefaultTTL

	for d.Next() {
		key := d.Val()
		var value string

		if key == "ns3" {
			ns3 = true
		}

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "address":
			if value != "" {
				address = value
			}
		case "username":
			if value != "" {
				username = value
			}
		case "password":
			if value != "" {
				password = value
			}
		case "prefix":
			if value != "" {
				prefix = value
			}
		case "ns":
			if value != "" {
				ns = append(ns, value)
			}
		case "ttl":
			if value != "" {
				duration, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return err
				}
				ttl = uint32(duration)
			}
		}
	}

	// Validate that at least one nameserver is configured
	if len(ns) == 0 {
		return d.Err("at least one nameserver must be configured")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Username: username,
		Password: password,
		DB:       0,
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(d).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &Nameshift{
			Next:        next,
			Client:      client,
			Prefix:      prefix,
			AddNs3:      ns3,
			Nameservers: ns,
			TTL:         ttl,
		}
	})

	// All OK, return a nil error.
	return nil
}
