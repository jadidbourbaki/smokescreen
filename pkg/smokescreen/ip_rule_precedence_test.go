package smokescreen

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

func TestIPRulePrecedence(t *testing.T) {
	tests := []struct {
		name, allow, deny, ip string
		port                  int
		want                  ipType
	}{
		{"narrow deny", "10.0.0.0/24", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"narrow allow", "10.0.0.5:443", "10.0.0.0/8", "10.0.0.5", 443, ipAllowUserConfigured},
		{"deny port", "10.0.0.5", "10.0.0.5:443", "10.0.0.5", 443, ipDenyUserConfigured},
		{"allow port", "10.0.0.5:443", "10.0.0.5", "10.0.0.5", 443, ipAllowUserConfigured},
		{"tie", "10.0.0.5:443", "10.0.0.5:443", "10.0.0.5", 443, ipDenyUserConfigured},
		{"CIDR address tie", "10.0.0.5/32", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"other port", "10.0.0.5", "10.0.0.5:443", "10.0.0.5", 80, ipAllowUserConfigured},
		{"IPv6", "fd00::/64", "[fd00::5]:443", "fd00::5", 443, ipDenyUserConfigured},
		{"mapped tie", "::ffff:10.0.0.5/128", "10.0.0.5", "10.0.0.5", 443, ipDenyUserConfigured},
		{"mapped port", "::ffff:10.0.0.5/128", "10.0.0.5:443", "::ffff:10.0.0.5", 443, ipDenyUserConfigured},
		{"loopback", "127.0.0.0/8", "127.0.0.5", "127.0.0.5", 443, ipDenyUserConfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConfig()
			c.IPRulePrecedence = IPRulePrecedenceMostSpecific
			for _, entry := range []struct {
				value string
				rules *[]RuleRange
			}{{tt.allow, &c.AllowRanges}, {tt.deny, &c.DenyRanges}} {
				var rules []RuleRange
				var err error
				if _, _, e := net.ParseCIDR(entry.value); e == nil {
					rules, err = parseRanges([]string{entry.value})
				} else {
					rules, err = parseAddresses([]string{entry.value})
				}
				require.NoError(t, err)
				*entry.rules = rules
			}
			require.Equal(t, tt.want, classifyAddr(c, &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: tt.port}))
		})
	}
}

func TestIPRulePrecedenceDefaultsAndSelfConnections(t *testing.T) {
	c := NewConfig()
	require.Equal(t, IPRulePrecedenceAllowFirst, c.IPRulePrecedence)
	require.NoError(t, c.SetAllowRanges([]string{"10.0.0.0/24"}))
	require.NoError(t, c.SetDenyAddresses([]string{"10.0.0.5"}))
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}
	for _, policy := range []IPRulePrecedence{"", IPRulePrecedenceAllowFirst, IPRulePrecedenceMostSpecific} {
		c.IPRulePrecedence = policy
		require.NoError(t, c.Validate())
		want := ipAllowUserConfigured
		if policy == IPRulePrecedenceMostSpecific {
			want = ipDenyUserConfigured
		}
		c.LocalIPs = nil
		c.AllowSelfConnections = false
		require.Equal(t, want, classifyAddr(c, addr))
		c.LocalIPs = []net.IP{addr.IP}
		require.Equal(t, ipDenySelfConnection, classifyAddr(c, addr))
		c.AllowSelfConnections = true
		require.Equal(t, want, classifyAddr(c, addr))
	}
	c.IPRulePrecedence = "unknown"
	require.Error(t, c.Validate())
}

func TestIPRulePrecedenceDefaultSafetyChecks(t *testing.T) {
	c := NewConfig()
	c.IPRulePrecedence = IPRulePrecedenceMostSpecific
	for _, tt := range []struct {
		ip   string
		want ipType
	}{{"10.0.0.1", ipDenyPrivateRange}, {"127.0.0.1", ipDenyNotGlobalUnicast}, {"100.64.0.1", ipDenyCGNAT}, {"64:ff9b::1", ipDenyIPv6Embedding}, {"8.8.8.8", ipAllowDefault}} {
		addr := &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: 443}
		require.Equal(t, tt.want, classifyAddr(c, addr))
		require.NoError(t, c.SetAllowAddresses([]string{tt.ip}))
		require.Equal(t, ipAllowUserConfigured, classifyAddr(c, addr))
	}
}

func TestIPRulePrecedenceProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	for _, tt := range []struct {
		name        string
		allow, deny string
		want        int
	}{
		{"broad allow narrow deny", "127.0.0.0/8", "127.0.0.1", http.StatusProxyAuthRequired},
		{"narrow allow broad deny", "127.0.0.1", "127.0.0.0/8", http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConfig()
			c.IPRulePrecedence = IPRulePrecedenceMostSpecific
			c.MetricsClient = metrics.NewNoOpMetricsClient()
			c.ConnTracker = conntrack.NewTracker(c.IdleTimeout, c.MetricsClient, c.Log, atomic.Value{}, nil)
			if tt.name == "broad allow narrow deny" {
				require.NoError(t, c.SetAllowRanges([]string{tt.allow}))
				require.NoError(t, c.SetDenyAddresses([]string{tt.deny}))
			} else {
				require.NoError(t, c.SetAllowAddresses([]string{tt.allow}))
				require.NoError(t, c.SetDenyRanges([]string{tt.deny}))
			}
			proxy := httptest.NewServer(BuildProxy(c))
			defer proxy.Close()
			proxyURL, err := url.Parse(proxy.URL)
			require.NoError(t, err)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			response, err := client.Get(target.URL)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, tt.want, response.StatusCode)
		})
	}
}

func TestIPRulePrecedenceRuleOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		c := NewConfig()
		c.IPRulePrecedence = IPRulePrecedenceMostSpecific
		allows := []string{"10.0.0.0/8", "10.0.0.0/24"}
		denies := []string{"10.0.0.0/16", "10.0.0.0/25"}
		if reverse {
			allows[0], allows[1] = allows[1], allows[0]
			denies[0], denies[1] = denies[1], denies[0]
		}
		require.NoError(t, c.SetAllowRanges(append(allows, allows...)))
		require.NoError(t, c.SetDenyRanges(append(denies, denies...)))
		require.Equal(t, ipDenyUserConfigured, classifyAddr(c, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}))
		require.Equal(t, ipAllowUserConfigured, classifyAddr(c, &net.TCPAddr{IP: net.ParseIP("10.0.0.200"), Port: 443}))
	}
}
