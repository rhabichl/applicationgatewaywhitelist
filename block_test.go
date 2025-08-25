package application_gateway_whitelist_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rhabichl/application_gateway_whitelist"
)

func TestIpv4EmptyAllowIPlist(t *testing.T) {
	cfg := application_gateway_whitelist.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := application_gateway_whitelist.New(ctx, next, cfg, "application_gateway_whitelist")
	if err == nil {
		t.Fatal("Error is nil but the AllowedIp List must be empty")
	}
	if fmt.Errorf("allowedIPs cannot be empty").Error() != err.Error() {
		t.Errorf("the error returned doesn't match.")
	}
}

func TestIpv4XForwardedFor(t *testing.T) {

	cases := []struct {
		Name          string
		AllowedIps    []string
		XForwardedFor string
		returnCode    int
	}{
		{"TestEmptyXForwardedFor", []string{"192.168.0.1"}, "", 400},
		{"TestTruePositiveWithOutPort", []string{"192.168.0.1"}, "192.168.0.1", 200},
		{"TestTrueNegativeWithOutPort", []string{"192.168.0.1"}, "192.168.0.2", 403},
		{"TestTruePositiveWithPort", []string{"192.168.0.1"}, "192.168.0.1:12346", 200},
		{"TestTrueNegativeWithOutPort", []string{"192.168.0.1"}, "192.168.0.2:13467", 403},
		{"TestRandomString", []string{"192.168.0.1"}, "Xwo?e]XvZ=qes(gM;Ay9nEUw&vJVL)\\]%.54=+)esT(Pa", 400},
		{"TestIpv6", []string{"192.168.0.1"}, "5d73:4f26:988f:9b52:c6af:4e83:7f4e:a47", 400},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(r *testing.T) {
			cfg := application_gateway_whitelist.CreateConfig()
			cfg.AllowedIP = tc.AllowedIps
			ctx := context.Background()

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(200)
			})

			handler, err := application_gateway_whitelist.New(ctx, next, cfg, "application_gateway_whitelist")
			if err != nil {
				r.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				r.Fatal(err)
			}
			req.Header.Add("X-Forwarded-for", tc.XForwardedFor)

			handler.ServeHTTP(recorder, req)

			if recorder.Result().StatusCode != tc.returnCode {
				r.Errorf("StatusCode didn't match! expected: %d but got: %d", tc.returnCode, recorder.Result().StatusCode)
			}
		})
	}

}
