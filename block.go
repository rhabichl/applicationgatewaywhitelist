package applicationgatewaywhitelist

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

type Config struct {
	AllowedIP []string `json:"headers,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AllowedIP: make([]string, 0),
	}
}

// Demo a Demo plugin.
type Application_gateway_whitelist struct {
	next       http.Handler
	allowedIPs []string
	name       string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.AllowedIP) == 0 {
		return nil, fmt.Errorf("allowedIPs cannot be empty")
	}

	return &Application_gateway_whitelist{
		allowedIPs: config.AllowedIP,
		next:       next,
		name:       name,
	}, nil
}

func (a *Application_gateway_whitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	// get IP from X-Forwarded-for header
	trueClientIP := req.Header.Get("X-Forwarded-for")
	if trueClientIP == "" {
		reject(http.StatusBadRequest, rw)
		return
	}
	// remove the port part
	addressParts := strings.Split(trueClientIP, ":")

	// parse the IPv4 address
	parsedAddr, err := netip.ParseAddr(strings.TrimSpace(addressParts[0]))
	if err != nil {
		reject(http.StatusBadRequest, rw)
		return
	}

	// iterate over all the ips and check if the client has the correct X-Forwarded-for header
	isClientAllowd := false
	for _, v := range a.allowedIPs {
		if v == parsedAddr.String() {
			isClientAllowd = true
		}
	}
	if !isClientAllowd {
		reject(http.StatusForbidden, rw)
		return
	}
	a.next.ServeHTTP(rw, req)
}

func reject(statusCode int, rw http.ResponseWriter) {
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		os.Stderr.WriteString(err.Error())
	}
}
