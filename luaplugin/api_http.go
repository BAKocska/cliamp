package luaplugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// allowedPrivateAddrs holds the non-public IP:port pairs that ssrfGuard lets
// through, from [plugins] allowed_private_addresses in config.toml: a
// self-hosted server on the machine or the home network. New sets it before
// any plugin runs.
var allowedPrivateAddrs atomic.Pointer[map[string]bool]

// ssrfGuard rejects connections to non-public addresses. It runs as the
// dialer's Control hook, so it sees the resolved IP for every connection
// attempt, including ones reached via HTTP redirects or DNS rebinding. An
// exact IP:port from allowedPrivateAddrs is let through; nothing wider is.
func ssrfGuard(network, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve dial address %q", address)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		if allowed := allowedPrivateAddrs.Load(); allowed != nil && (*allowed)[net.JoinHostPort(ip.String(), port)] {
			return nil
		}
		return fmt.Errorf("blocked request to non-public address %s", ip)
	}
	return nil
}

// resolveAllowedPrivateAddrs reads [plugins] allowed_private_addresses =
// "ip:port,ip:port". Only literal IPs with a port count: the guard sees resolved
// addresses, and a host name could be pointed elsewhere. Entries that are not
// ip:port with a port from 1 to 65535 are skipped and returned in invalid, so New
// can log them.
func resolveAllowedPrivateAddrs(pluginCfg map[string]map[string]string) (allowed map[string]bool, invalid []string) {
	raw := pluginCfg[""]["allowed_private_addresses"]
	allowed = make(map[string]bool)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port, err := net.SplitHostPort(entry)
		ip := net.ParseIP(host)
		// the dialer reports ports in plain decimal, so "08085" must become "8085"
		number, portErr := strconv.Atoi(port)
		if err != nil || ip == nil || portErr != nil || number < 1 || number > 65535 {
			invalid = append(invalid, entry)
			continue
		}
		allowed[net.JoinHostPort(ip.String(), strconv.Itoa(number))] = true
	}
	return allowed, invalid
}

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			Control: ssrfGuard,
		}).DialContext,
	},
}

// registerHTTPAPI adds cliamp.http.{get,post} to the cliamp table.
func registerHTTPAPI(L *lua.LState, cliamp *lua.LTable) {
	tbl := L.NewTable()

	// cliamp.http.get(url, opts?) -> body, status
	L.SetField(tbl, "get", L.NewFunction(func(L *lua.LState) int {
		return doHTTP(L, "GET")
	}))

	// cliamp.http.post(url, opts?) -> body, status
	L.SetField(tbl, "post", L.NewFunction(func(L *lua.LState) int {
		return doHTTP(L, "POST")
	}))

	L.SetField(cliamp, "http", tbl)
}

const maxResponseBody = 1 << 20 // 1MB

func doHTTP(L *lua.LState, method string) int {
	rawURL := L.CheckString(1)
	if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return pushErr(L, "only http and https URLs are allowed")
	}
	opts := L.OptTable(2, nil)

	var bodyReader io.Reader
	if opts != nil {
		// JSON body: cliamp.http.post(url, {json = {...}})
		if jsonVal := opts.RawGetString("json"); jsonVal != lua.LNil {
			goVal := luaToGo(jsonVal)
			data, err := json.Marshal(goVal)
			if err != nil {
				return pushErr(L, err.Error())
			}
			bodyReader = strings.NewReader(string(data))
		}

		// Raw body: cliamp.http.post(url, {body = "..."})
		if body := opts.RawGetString("body"); body != lua.LNil {
			bodyReader = strings.NewReader(body.String())
		}
	}

	req, err := http.NewRequestWithContext(callContext(L), method, rawURL, bodyReader)
	if err != nil {
		return pushErr(L, err.Error())
	}

	// Apply headers from opts.
	if opts != nil {
		if hdrs := opts.RawGetString("headers"); hdrs != lua.LNil {
			if tbl, ok := hdrs.(*lua.LTable); ok {
				tbl.ForEach(func(k, v lua.LValue) {
					req.Header.Set(k.String(), v.String())
				})
			}
		}
		// Auto-set Content-Type for JSON if not explicitly set.
		if opts.RawGetString("json") != lua.LNil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return pushErr(L, err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return pushErr(L, err.Error())
	}

	L.Push(lua.LString(string(body)))
	L.Push(lua.LNumber(resp.StatusCode))
	return 2
}
