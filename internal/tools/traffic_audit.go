package tools

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// TrafficAudit is what this host is doing on the network right now.
//
// It is worth being precise about what this is, because "traffic inspection"
// invites the wrong mental model. This does NOT capture packets. It reads the
// kernel's own connection tables under /proc, which is state the machine is
// already exposing to any process running as the same user. There is no
// promiscuous mode, no root requirement, and nothing here can observe another
// machine's traffic or the contents of an encrypted session.
type TrafficAudit struct {
	Host        string         `json:"host"`
	CollectedAt string         `json:"collected_at"`
	Listening   []ListenSocket `json:"listening_sockets"`
	Established []RemotePeer   `json:"established_connections"`
	Plaintext   []Finding      `json:"plaintext_exposure,omitempty"`
	Exposure    []Finding      `json:"exposed_services,omitempty"`
	Neighbors   []ARPNeighbor  `json:"arp_neighbors,omitempty"`
	Routes      []RouteEntry   `json:"routes,omitempty"`
	NameServers []string       `json:"name_servers,omitempty"`
	DNSResolver string         `json:"resolver_configured,omitempty"`
	Summary     TrafficSummary `json:"summary"`
	Limitations []string       `json:"limitations"`
}

// ListenSocket is a bound port waiting for a connection.
type ListenSocket struct {
	Proto     string `json:"proto"`
	Local     string `json:"local_address"`
	Port      int    `json:"port"`
	Wildcard  bool   `json:"wildcard_bind"`
	Process   string `json:"process,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Exposed   bool   `json:"reachable_off_host"`
	Sensitive bool   `json:"sensitive_service"`
}

// RemotePeer is one outbound connection.
type RemotePeer struct {
	Proto     string `json:"proto"`
	LocalPort int    `json:"local_port"`
	Remote    string `json:"remote_address"`
	Port      int    `json:"remote_port"`
	Process   string `json:"process,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Direction string `json:"direction"`
	Plaintext bool   `json:"plaintext"`
	Note      string `json:"note,omitempty"`
}

// ARPNeighbor is a host the kernel has on the local segment.
type ARPNeighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface,omitempty"`
	State     string `json:"state,omitempty"`
	Vendor    string `json:"vendor_hint,omitempty"`
}

// RouteEntry is one line of the routing table.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

// TrafficSummary is the answer-first view.
type TrafficSummary struct {
	ListeningCount   int      `json:"listening_ports"`
	WorldReachable   []string `json:"world_reachable,omitempty"`
	EstablishedCount int      `json:"established_connections"`
	PlaintextCount   int      `json:"plaintext_connections"`
	SensitiveCount   int      `json:"sensitive_services_listening"`
	DefaultRouteVia  string   `json:"default_gateway,omitempty"`
	Verdict          string   `json:"verdict"`
}

// sensitiveService identifies a port that is dangerous to expose without
// authentication. Redis, MongoDB and Memcached ship with no auth by default and
// are a very common way an assessment turns into an incident.
var sensitivePorts = map[int]string{
	21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
	445: "smb", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
	5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// cleartextPorts identifies protocols that carry credentials or payload in the
// clear. A connection to one of these is an observation worth reporting.
var cleartextPorts = map[int]string{
	21:   "FTP sends credentials in the clear",
	23:   "Telnet is an unencrypted terminal protocol",
	25:   "SMTP without STARTTLS relays mail in the clear",
	110:  "POP3 without TLS carries the password in the clear",
	143:  "IMAP without TLS carries the password in the clear",
	80:   "HTTP is unencrypted by definition",
	8080: "HTTP on an alternate port is still unencrypted",
}

func trafficAuditTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_traffic_audit",
		mcp.WithDescription(
			"Observe this machine's network activity from the kernel's own connection tables: every "+
				"listening port, every established outbound connection with the owning process, ARP "+
				"neighbours, the routing table and the configured resolver. "+
				"Use it to answer \"what is this host doing on the network, what is it exposing, and "+
				"what is talking to it\" before an assessment — unexpected listeners, a process talking "+
				"to a database over cleartext, or a management port bound to every interface all show up "+
				"here. "+
				"LIMITATIONS, which matter: this reads /proc connection state, it does not capture "+
				"packets. It cannot see another machine's traffic, cannot decrypt TLS, and shows no "+
				"payload. It is a snapshot, not a recording. "+
				"Reads only; it opens no socket and changes nothing.",
		),
		mcp.WithToolTitle("SENTINEL-X Local Traffic & Exposure Audit"),
		mcp.WithBoolean("include_routes",
			mcp.Description("Include the routing table and ARP neighbours. Useful for understanding which segment the host is on."),
			mcp.DefaultBool(true),
		),
		mcp.WithBoolean("include_processes",
			mcp.Description("Resolve sockets to owning processes by scanning /proc. Shows fewer sockets without it when the process belongs to another user."),
			mcp.DefaultBool(true),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_traffic_audit"

		if d.Cfg != nil && d.Cfg.Policy.EnforceScope {
			// The tool only ever inspects the local machine, but the check keeps
			// the guarantee uniform: an enforced scope never silently produces
			// output, even about itself.
			if err := scopeCheck(d, "127.0.0.1"); err != nil && !isLoopbackScopeRefusal(err) {
				return fail(toolName, "127.0.0.1", start, err)
			}
		}

		data, err := collectTraffic(req.GetBool("include_processes", true),
			req.GetBool("include_routes", true))
		if err != nil {
			return fail(toolName, "127.0.0.1", start, err)
		}

		var warn []string
		if !req.GetBool("include_processes", true) {
			warn = append(warn, "process attribution was not requested, so sockets show no owning program")
		}
		if !isPrivileged() {
			warn = append(warn, "not running as root: sockets owned by other users are listed without a process name")
		}
		return ok(d, toolName, "127.0.0.1", start, nil, data, warn...)
	}

	return Tool{Tool: t, Handler: h}
}

func isLoopbackScopeRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "127.0.0.1")
}

func isPrivileged() bool { return os.Geteuid() == 0 }

// collectTraffic reads the kernel tables. Every read is best-effort: a system
// without /proc/net (a container with it masked, for instance) yields an empty
// report with an explanation rather than a failed call, because "I could not
// look" and "there is nothing there" must not look the same.
func collectTraffic(withProcs, withRoutes bool) (TrafficAudit, error) {
	host, _ := os.Hostname()
	out := TrafficAudit{
		Host: host, CollectedAt: now(),
		Listening: []ListenSocket{}, Established: []RemotePeer{},
		Neighbors: []ARPNeighbor{}, Routes: []RouteEntry{}, NameServers: []string{},
		Limitations: []string{
			"this is kernel connection state under /proc, not packet capture: no payloads, no timings, no protocol decoding",
			"it cannot see traffic on another machine, and it cannot decrypt an encrypted session",
			"it is a point-in-time snapshot; a connection opened after the call is not visible",
			"a process that is not running is not visible, and a connection that closed before the call is gone",
		},
	}

	owners := map[string]socketOwner{}
	if withProcs {
		owners = procOwners()
	}

	for _, f := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
	} {
		for _, s := range parseProcNet(f.path, f.proto, owners, withProcs) {
			if s.Established {
				out.Established = append(out.Established, s.Peer)
			} else {
				out.Listening = append(out.Listening, s.Listener)
			}
		}
	}
	for _, f := range []struct{ path, proto string }{
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		for _, s := range parseProcNet(f.path, f.proto, owners, withProcs) {
			// A UDP socket with a bound port is a listener; the ones with no
			// local port are transient client sockets and are not interesting.
			if s.Listener.Port != 0 {
				out.Listening = append(out.Listening, s.Listener)
			}
		}
	}

	if withRoutes {
		out.Routes = parseProcRoute()
		out.Neighbors = parseProcArp()
	}
	out.NameServers = parseResolvConf()

	out.Plaintext = plaintextFindings(out.Listening, out.Established)
	out.Exposure = exposureFindings(out.Listening)
	out.Summary = summarise(out)
	return out, nil
}

type parsedSocket struct {
	Listener    ListenSocket
	Peer        RemotePeer
	Established bool
}

type socketOwner struct {
	Name string
	PID  int
}

// procOwners maps socket inodes to processes. Without root this only resolves
// sockets this user owns, which is stated in the report rather than presented
// as a complete picture.
func procOwners() map[string]socketOwner {
	owners := map[string]socketOwner{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	self := map[int]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		self[pid] = true
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // not ours
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if ino == "" {
				continue
			}
			owners[ino] = socketOwner{Name: processName(pid), PID: pid}
		}
	}
	return owners
}

func processName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseProcNet reads one /proc/net table. The format is positional and
// column-delimited: sl, local_address, rem_address, st, ... inode is field 9.
// A row that does not match is skipped rather than aborting the file, so one
// malformed line cannot lose the whole table.
func parseProcNet(path, proto string, owners map[string]socketOwner, withProcs bool) []parsedSocket {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	var out []parsedSocket
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Fields(line)
		if len(cols) < 10 {
			continue
		}
		lAddr, lPort, ok := decodeHexAddr(cols[1])
		if !ok {
			continue
		}
		rAddr, rPort, _ := decodeHexAddr(cols[2])
		state, _ := strconv.ParseUint(cols[3], 16, 32)

		own := owners[cols[9]]
		if !withProcs {
			own = socketOwner{}
		}

		// 0A is TCP_LISTEN. UDP has no state column, so port 0 means an
		// unbound client socket.
		isListen := state == 0x0A || (strings.HasPrefix(proto, "udp") && rAddr == "0.0.0.0" && rPort == 0)

		ps := parsedSocket{}
		if isListen {
			ps.Listener = ListenSocket{
				Proto: proto, Local: lAddr, Port: lPort,
				Wildcard: isWildcard(lAddr), Process: own.Name, PID: own.PID,
			}
			ps.Listener.Exposed = ps.Listener.Wildcard && !isLoopbackAddr(lAddr)
			_, ps.Listener.Sensitive = sensitivePorts[lPort]
		} else {
			ps.Established = true
			ps.Peer = RemotePeer{
				Proto: proto, LocalPort: lPort, Remote: rAddr, Port: rPort,
				Process: own.Name, PID: own.PID, Direction: "outbound",
			}
			if note, plain := cleartextPorts[rPort]; plain {
				ps.Peer.Plaintext = true
				ps.Peer.Note = note
			}
		}
		out = append(out, ps)
	}
	return out
}

// decodeHexAddr decodes the "0100007F:1F90" form: little-endian IPv4 in hex,
// IPv6 in 4 little-endian words.
func decodeHexAddr(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(s[i+1:], 16, 32)
	if err != nil {
		return "", 0, false
	}
	hexAddr := s[:i]
	if len(hexAddr) != 8 && len(hexAddr) != 32 {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || len(raw) != 4 && len(raw) != 16 {
		return "", 0, false
	}
	if len(raw) == 4 {
		// The kernel writes IPv4 words in host order, so reverse the word.
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), int(port64), true
	}
	b := make([]byte, 16)
	for w := 0; w < 4; w++ {
		for i := 0; i < 4; i++ {
			b[w*4+i] = raw[w*4+3-i]
		}
	}
	return net.IP(b).String(), int(port64), true
}

func isWildcard(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "::0"
}

func isLoopbackAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1"
}

func plaintextFindings(listen []ListenSocket, peers []RemotePeer) []Finding {
	var out []Finding
	for _, p := range peers {
		if !p.Plaintext {
			continue
		}
		who := p.Process
		if who == "" {
			who = fmt.Sprintf("pid %d", p.PID)
		}
		out = append(out, Finding{
			Severity: "medium",
			Summary:  fmt.Sprintf("Outbound cleartext connection to %s:%d", p.Remote, p.Port),
			Evidence: fmt.Sprintf("%s (%s) — %s", who, p.Proto, p.Note),
			Remediate: "Move the channel to TLS. Whatever this connection carries is on the wire in " +
				"plaintext, readable by anyone on the path.",
		})
	}
	seen := map[string]bool{}
	var deduped []Finding
	for _, f := range out {
		k := f.Summary
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, f)
	}
	return deduped
}

func exposureFindings(listen []ListenSocket) []Finding {
	var out []Finding
	for _, s := range listen {
		if !s.Sensitive || !s.Exposed {
			continue
		}
		svc := sensitivePorts[s.Port]
		who := s.Process
		if who == "" {
			who = fmt.Sprintf("pid %d", s.PID)
		}
		sev := "high"
		rem := "Bind it to a loopback address, or firewall it so it is reachable only from the network " +
			"that needs it. These services frequently ship with no authentication at all."
		if s.Port == 2049 {
			sev = "medium"
			rem = "NFS exports directory trees to anyone who can reach the port. Restrict to the clients that need them."
		}
		out = append(out, Finding{
			Severity:  sev,
			Summary:   fmt.Sprintf("%s is bound to every interface", svc),
			Evidence:  fmt.Sprintf("port %d/%s listening on %s, owned by %s", s.Port, s.Proto, s.Local, who),
			Remediate: rem,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return out
}

func parseProcRoute() []RouteEntry { return parseProcRouteFrom("/proc/net/route") }

// parseProcRouteFrom takes the path so the parser can be tested against a
// fixture rather than only against whatever this machine happens to have.
func parseProcRouteFrom(path string) []RouteEntry {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	var out []RouteEntry
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		c := strings.Fields(line)
		if len(c) < 8 {
			continue
		}
		out = append(out, RouteEntry{
			Destination: hexToIPv4(c[1]),
			Gateway:     hexToIPv4(c[2]),
			Interface:   c[0],
			Flags:       c[3],
			Metric:      atoiSafe(c[6]),
		})
	}
	return out
}

func parseProcArp() []ARPNeighbor { return parseProcArpFrom("/proc/net/arp") }

func parseProcArpFrom(path string) []ARPNeighbor {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	var out []ARPNeighbor
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		c := strings.Fields(line)
		if len(c) < 6 {
			continue
		}
		n := ARPNeighbor{IP: c[0], MAC: c[3], Interface: c[5], State: c[2]}
		if n.MAC == "00:00:00:00:00:00" {
			// An unresolved entry means an ARP request went unanswered.
			n.State = "incomplete"
		}
		out = append(out, n)
	}
	return out
}

func parseResolvConf() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "nameserver") {
			if parts := strings.Fields(l); len(parts) >= 2 {
				out = append(out, parts[1])
			}
		}
	}
	return out
}

func hexToIPv4(s string) string {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return ""
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

func atoiSafe(s string) int { v, _ := strconv.Atoi(s); return v }

func summarise(t TrafficAudit) TrafficSummary {
	s := TrafficSummary{
		ListeningCount: len(t.Listening), EstablishedCount: len(t.Established),
		PlaintextCount: len(t.Plaintext),
	}
	for _, l := range t.Listening {
		if l.Sensitive {
			s.SensitiveCount++
		}
		if l.Exposed {
			s.WorldReachable = append(s.WorldReachable,
				fmt.Sprintf("%d/%s %s", l.Port, l.Proto, orNone(l.Process)))
		}
	}
	for _, r := range t.Routes {
		if r.Destination == "0.0.0.0" {
			s.DefaultRouteVia = r.Gateway + " via " + r.Interface
		}
	}
	s.WorldReachable = dedupe(s.WorldReachable)

	switch {
	case len(t.Plaintext) > 0 || len(t.Exposure) > 0:
		s.Verdict = fmt.Sprintf("%d finding(s): %d cleartext connection(s) and %d sensitive service(s) reachable off-host",
			len(t.Plaintext)+len(t.Exposure), len(t.Plaintext), len(t.Exposure))
	case len(t.Listening) == 0:
		s.Verdict = "no listening sockets and no outbound connections were visible from this user's view"
	default:
		s.Verdict = fmt.Sprintf("%d listening port(s), none of them a sensitive service reachable off-host",
			len(t.Listening))
	}
	return s
}
