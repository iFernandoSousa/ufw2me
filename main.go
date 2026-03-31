package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed frontend/*
var frontendFS embed.FS

// Rule represents a single UFW firewall rule
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	IPs         []string `json:"ips"`
	Protocol    string   `json:"protocol"`
	Port        string   `json:"port"`
	PortRange   string   `json:"port_range"`
	Direction   string   `json:"direction"` // "in" or "out"
	Action      string   `json:"action"`    // "allow" or "deny"
	Interface   string   `json:"interface"`
	Order       int      `json:"order"`
}

// RulesPayload is used for saving rules
type RulesPayload struct {
	Rules []Rule `json:"rules"`
}

// StatusResponse holds the UFW status
type StatusResponse struct {
	Active     bool   `json:"active"`
	Status     string `json:"status"`
	RuleCount  int    `json:"rule_count"`
	Interfaces []NetworkInterface `json:"interfaces"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	Status string `json:"status"`
}

var (
	port    string
	devMode bool
	mu      sync.Mutex
)

func init() {
	port = os.Getenv("UFW2ME_PORT")
	if port == "" {
		port = "9850"
	}
	devMode = os.Getenv("UFW2ME_DEV") == "1"
}

func main() {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", corsMiddleware(handleStatus))
	mux.HandleFunc("/api/rules", corsMiddleware(handleRules))
	mux.HandleFunc("/api/rules/save", corsMiddleware(handleSaveRules))
	mux.HandleFunc("/api/interfaces", corsMiddleware(handleInterfaces))
	mux.HandleFunc("/api/ufw/toggle", corsMiddleware(handleToggleUFW))

	// Serve frontend
	frontendContent, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	fileServer := http.FileServer(http.FS(frontendContent))
	mux.Handle("/", fileServer)

	addr := fmt.Sprintf(":%s", port)
	log.Printf("🔥 ufw2me starting on http://0.0.0.0%s", addr)
	log.Printf("   Mode: %s", func() string {
		if devMode {
			return "development (mock)"
		}
		return "production"
	}())

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ─── UFW Command Helpers ─────────────────────────────────────

func runUFW(args ...string) (string, error) {
	if devMode {
		return mockUFW(args...)
	}
	cmd := exec.Command("ufw", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mockUFW(args ...string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "status":
		return `Status: active

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
5432/tcp                   ALLOW       143.0.190.9
22/tcp                     ALLOW       201.92.92.185
22/tcp                     ALLOW       177.9.202.231
8000/tcp                   ALLOW       Anywhere
Anywhere                   ALLOW OUT   Anywhere (out)
80/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
8000/tcp (v6)              ALLOW       Anywhere (v6)
Anywhere (v6)              ALLOW OUT   Anywhere (v6) (out)
`, nil
	case "show":
		return `Status: active

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
5432/tcp                   ALLOW IN    143.0.190.9
22/tcp                     ALLOW IN    201.92.92.185
22/tcp                     ALLOW IN    177.9.202.231
8000/tcp                   ALLOW IN    Anywhere
Anywhere                   ALLOW OUT   Anywhere
`, nil
	default:
		return "Rule added", nil
	}
}

func getInterfaces() []NetworkInterface {
	if devMode {
		return []NetworkInterface{
			{Name: "eth0", Addr: "10.0.0.5", Status: "up"},
			{Name: "lo", Addr: "127.0.0.1", Status: "up"},
		}
	}

	out, err := exec.Command("ip", "-br", "addr").CombinedOutput()
	if err != nil {
		// Fallback for macOS
		out, err = exec.Command("ifconfig").CombinedOutput()
		if err != nil {
			return nil
		}
		return parseIfconfig(string(out))
	}
	return parseIPAddr(string(out))
}

func parseIPAddr(output string) []NetworkInterface {
	var ifaces []NetworkInterface
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := NetworkInterface{
			Name:   fields[0],
			Status: strings.ToLower(fields[1]),
		}
		if len(fields) >= 3 {
			addr := fields[2]
			if idx := strings.Index(addr, "/"); idx > 0 {
				addr = addr[:idx]
			}
			iface.Addr = addr
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func parseIfconfig(output string) []NetworkInterface {
	var ifaces []NetworkInterface
	blocks := strings.Split(output, "\n\n")
	for _, block := range blocks {
		lines := strings.Split(block, "\n")
		if len(lines) == 0 {
			continue
		}
		// First line has the interface name
		firstLine := lines[0]
		colonIdx := strings.Index(firstLine, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(firstLine[:colonIdx])
		iface := NetworkInterface{Name: name, Status: "up"}

		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "inet ") {
				fields := strings.Fields(l)
				if len(fields) >= 2 {
					iface.Addr = fields[1]
				}
			}
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

// ─── API Handlers ────────────────────────────────────────────

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	out, err := runUFW("status")
	if err != nil && !devMode {
		jsonError(w, "Failed to get UFW status: "+err.Error(), 500)
		return
	}

	active := strings.Contains(out, "Status: active")
	rules := parseUFWRules(out)

	resp := StatusResponse{
		Active:     active,
		Status:     func() string { if active { return "active" }; return "inactive" }(),
		RuleCount:  len(rules),
		Interfaces: getInterfaces(),
	}
	jsonResponse(w, resp)
}

func handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	out, err := runUFW("status")
	if err != nil && !devMode {
		jsonError(w, "Failed to get UFW rules: "+err.Error(), 500)
		return
	}

	rules := parseUFWRules(out)
	jsonResponse(w, rules)
}

func handleSaveRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	var payload RulesPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonError(w, "Invalid JSON: "+err.Error(), 400)
		return
	}

	if devMode {
		log.Printf("DEV MODE: Would apply %d rules", len(payload.Rules))
		for i, rule := range payload.Rules {
			log.Printf("  Rule %d: %s %s %s:%s from %v", i+1, rule.Direction, rule.Action, rule.Protocol, rule.Port, rule.IPs)
		}
		jsonResponse(w, map[string]string{"status": "ok", "message": "Rules applied (dev mode)"})
		return
	}

	// 1. Reset UFW rules (keeping UFW active)
	cmd := exec.Command("ufw", "--force", "reset")
	if out, err := cmd.CombinedOutput(); err != nil {
		jsonError(w, "Failed to reset UFW: "+string(out), 500)
		return
	}

	// 2. Re-enable UFW
	cmd = exec.Command("ufw", "--force", "enable")
	if out, err := cmd.CombinedOutput(); err != nil {
		jsonError(w, "Failed to enable UFW: "+string(out), 500)
		return
	}

	// 3. Apply each rule in order
	for _, rule := range payload.Rules {
		args := buildUFWArgs(rule)
		if len(args) == 0 {
			continue
		}
		cmd = exec.Command("ufw", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: Failed to apply rule: %s - %s", strings.Join(args, " "), string(out))
		}
	}

	// 4. Reload
	cmd = exec.Command("ufw", "reload")
	cmd.CombinedOutput()

	jsonResponse(w, map[string]string{"status": "ok", "message": "Rules applied successfully"})
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	jsonResponse(w, getInterfaces())
}

func handleToggleUFW(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	var body struct {
		Enable bool `json:"enable"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	action := "disable"
	if body.Enable {
		action = "enable"
	}

	if devMode {
		log.Printf("DEV MODE: Would %s UFW", action)
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	cmd := exec.Command("ufw", "--force", action)
	out, err := cmd.CombinedOutput()
	if err != nil {
		jsonError(w, "Failed to toggle UFW: "+string(out), 500)
		return
	}

	jsonResponse(w, map[string]string{"status": "ok"})
}

// ─── UFW Parsing ─────────────────────────────────────────────

func parseUFWRules(output string) []Rule {
	var rules []Rule
	lines := strings.Split(output, "\n")
	ruleSection := false
	order := 0

	// Track which rules we've seen to merge v4/v6
	type ruleKey struct {
		port      string
		action    string
		direction string
		from      string
	}
	seen := make(map[ruleKey]int) // key -> index in rules

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "To") {
			ruleSection = true
			continue
		}
		if !ruleSection || line == "" {
			continue
		}

		rule := parseRuleLine(line, order)
		if rule.Port == "" && rule.Action == "" {
			continue
		}

		// Determine if this is a v6 rule
		isV6 := strings.Contains(line, "(v6)")

		key := ruleKey{
			port:      rule.Port,
			action:    rule.Action,
			direction: rule.Direction,
			from:      strings.Join(rule.IPs, ","),
		}

		if idx, exists := seen[key]; exists {
			// Merge: add v6 indicator
			if isV6 {
				hasV4 := false
				hasV6 := false
				for _, ip := range rules[idx].IPs {
					if ip == "Any IPv4" { hasV4 = true }
					if ip == "Any IPv6" { hasV6 = true }
				}
				if hasV4 && !hasV6 {
					rules[idx].IPs = append(rules[idx].IPs, "Any IPv6")
				}
			}
		} else {
			// If it's a v6-only rule with "Anywhere (v6)", mark as IPv6
			if isV6 && len(rule.IPs) > 0 && rule.IPs[0] == "Any IPv4" {
				rule.IPs = []string{"Any IPv6"}
			}
			order++
			rule.Order = order
			rule.ID = fmt.Sprintf("rule-%d", order)
			seen[key] = len(rules)
			rules = append(rules, rule)
		}
	}

	return rules
}

func parseRuleLine(line string, order int) Rule {
	rule := Rule{
		Direction: "in",
		Action:    "allow",
		Protocol:  "TCP",
	}

	// Detect direction
	if strings.Contains(line, "OUT") || strings.Contains(line, "(out)") {
		rule.Direction = "out"
	}

	// Parse action
	if strings.Contains(line, "DENY") {
		rule.Action = "deny"
	} else if strings.Contains(line, "REJECT") {
		rule.Action = "reject"
	}

	// Regex to parse standard UFW status lines
	// Format: "To    Action    From"
	// Example: "80/tcp    ALLOW    Anywhere"
	// Example: "22/tcp    ALLOW    201.92.92.185"

	parts := regexp.MustCompile(`\s{2,}`).Split(line, -1)
	if len(parts) < 3 {
		return rule
	}

	to := strings.TrimSpace(parts[0])
	from := strings.TrimSpace(parts[len(parts)-1])

	// Parse port/protocol from "To" column
	to = strings.Replace(to, " (v6)", "", 1)
	if strings.Contains(to, "/") {
		pp := strings.SplitN(to, "/", 2)
		rule.Port = pp[0]
		rule.Protocol = strings.ToUpper(pp[1])
	} else if to == "Anywhere" || to == "Anywhere (v6)" {
		rule.Port = "any"
	} else {
		rule.Port = to
	}

	// Parse "From" column
	from = strings.Replace(from, "(out)", "", 1)
	from = strings.TrimSpace(from)
	if from == "Anywhere" || from == "Anywhere (v6)" {
		rule.IPs = []string{"Any IPv4"}
	} else {
		rule.IPs = []string{from}
	}

	// Handle port ranges
	if strings.Contains(rule.Port, ":") {
		rangeParts := strings.SplitN(rule.Port, ":", 2)
		rule.Port = rangeParts[0]
		rule.PortRange = rangeParts[1]
	}

	return rule
}

func buildUFWArgs(rule Rule) []string {
	var args []string

	action := rule.Action
	if action == "" {
		action = "allow"
	}

	direction := "in"
	if rule.Direction == "out" {
		direction = "out"
	}

	// Build port spec
	port := rule.Port
	if rule.PortRange != "" {
		port = port + ":" + rule.PortRange
	}

	proto := strings.ToLower(rule.Protocol)
	if proto == "" {
		proto = "tcp"
	}

	for _, ip := range rule.IPs {
		fromIP := ""
		switch ip {
		case "Any IPv4", "Any IPv6", "":
			fromIP = ""
		default:
			fromIP = ip
		}

		args = []string{action, direction}

		if fromIP != "" {
			args = append(args, "from", fromIP)
		}

		if port != "" && port != "any" {
			args = append(args, "to", "any", "port", port, "proto", proto)
		}

		// Execute for each IP
		if len(args) > 0 {
			return args
		}
	}

	if len(rule.IPs) == 0 {
		args = []string{action, direction}
		if port != "" && port != "any" {
			args = append(args, "to", "any", "port", port, "proto", proto)
		}
		return args
	}

	return args
}

// unused but kept for completeness
var _ = strconv.Itoa
