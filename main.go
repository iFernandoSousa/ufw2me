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
	Active     bool               `json:"active"`
	Status     string             `json:"status"`
	RuleCount  int                `json:"rule_count"`
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
	applyConfigFromFiles()
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
		Active: active,
		Status: func() string {
			if active {
				return "active"
			}
			return "inactive"
		}(),
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
		cmds := buildUFWCommands(rule)
		for _, args := range cmds {
			if len(args) == 0 {
				continue
			}
			cmd = exec.Command("ufw", args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Warning: Failed to apply rule: %s - %s", strings.Join(args, " "), string(out))
			}
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
		if strings.HasPrefix(line, "To") || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "---") {
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
					if ip == "Any IPv4" {
						hasV4 = true
					}
					if ip == "Any IPv6" {
						hasV6 = true
					}
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

	// Regex to parse standard UFW status lines
	// Format: "To    Action    From"
	// Example: "80/tcp    ALLOW    Anywhere"
	// Example: "22/tcp    ALLOW    201.92.92.185"

	parts := regexp.MustCompile(`\s{2,}`).Split(line, -1)
	if len(parts) < 3 {
		return rule
	}

	toCol := strings.TrimSpace(parts[0])
	actionCol := strings.ToUpper(strings.TrimSpace(parts[1]))
	fromCol := strings.TrimSpace(parts[len(parts)-1])

	if strings.Contains(actionCol, "OUT") || strings.Contains(line, "(out)") {
		rule.Direction = "out"
	}

	if strings.Contains(actionCol, "DENY") {
		rule.Action = "deny"
	} else if strings.Contains(actionCol, "REJECT") {
		rule.Action = "reject"
	} else {
		rule.Action = "allow"
	}

	// Parse port/protocol from "To" column
	toCol = strings.Replace(toCol, " (v6)", "", 1)
	toCol, rule.Interface = splitInterface(toCol)
	toSpec, toIP := splitToSpecAndIP(toCol)

	if strings.Contains(toSpec, "/") {
		pp := strings.SplitN(toSpec, "/", 2)
		rule.Port = pp[0]
		rule.Protocol = strings.ToUpper(pp[1])
	} else if toSpec == "Anywhere" || toSpec == "" {
		rule.Port = "any"
	} else {
		rule.Port = toSpec
	}

	// Parse "From" column
	fromCol = strings.Replace(fromCol, "(out)", "", 1)
	fromCol = strings.TrimSpace(fromCol)

	if rule.Direction == "out" {
		if toIP == "Anywhere" || toIP == "" {
			rule.IPs = []string{"Any IPv4"}
		} else if toIP == "Anywhere (v6)" {
			rule.IPs = []string{"Any IPv6"}
		} else {
			rule.IPs = []string{toIP}
		}
	} else {
		if fromCol == "Anywhere" || fromCol == "Anywhere (v6)" {
			rule.IPs = []string{"Any IPv4"}
		} else {
			rule.IPs = []string{fromCol}
		}
	}

	// Handle port ranges
	if strings.Contains(rule.Port, ":") {
		rangeParts := strings.SplitN(rule.Port, ":", 2)
		rule.Port = rangeParts[0]
		rule.PortRange = rangeParts[1]
	}

	return rule
}

func buildUFWCommands(rule Rule) [][]string {
	action := rule.Action
	if action == "" {
		action = "allow"
	}

	direction := "in"
	if rule.Direction == "out" {
		direction = "out"
	}

	port := strings.TrimSpace(rule.Port)
	portRange := strings.TrimSpace(rule.PortRange)
	if port != "" && portRange != "" {
		port = port + ":" + portRange
	}

	proto := strings.ToLower(rule.Protocol)
	if proto == "" {
		proto = "tcp"
	}

	ipValues := normalizeIPs(rule.IPs)
	if len(ipValues) == 0 {
		ipValues = []string{""}
	}

	var cmds [][]string
	for _, ip := range ipValues {
		args := []string{action, direction}
		if rule.Interface != "" {
			args = append(args, "on", rule.Interface)
		}

		if direction == "in" {
			if ip != "" {
				args = append(args, "from", ip)
			}
			if port != "" && port != "any" {
				args = append(args, "to", "any", "port", port, "proto", proto)
			}
		} else {
			if ip != "" {
				args = append(args, "to", ip)
			} else {
				args = append(args, "to", "any")
			}
			if port != "" && port != "any" {
				args = append(args, "port", port, "proto", proto)
			}
		}

		cmds = append(cmds, args)
	}

	return cmds
}

// unused but kept for completeness
var _ = strconv.Itoa

func applyConfigFromFiles() {
	paths := []string{
		"/etc/ufw2me.env",
		"./ufw2me.env",
	}
	for _, p := range paths {
		applyEnvFile(p)
	}
}

func applyEnvFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, val)
	}
}

func splitInterface(toCol string) (string, string) {
	re := regexp.MustCompile(`\s+on\s+([^\s]+)\s*$`)
	m := re.FindStringSubmatch(toCol)
	if len(m) == 2 {
		toCol = strings.TrimSpace(re.ReplaceAllString(toCol, ""))
		return toCol, m[1]
	}
	return toCol, ""
}

func splitToSpecAndIP(toCol string) (string, string) {
	tokens := strings.Fields(toCol)
	if len(tokens) >= 2 && isLikelyIPToken(tokens[0]) {
		return tokens[1], tokens[0]
	}
	return toCol, ""
}

func isLikelyIPToken(token string) bool {
	if token == "Anywhere" || token == "Anywhere (v6)" {
		return true
	}

	if strings.Contains(token, "/") {
		left, right, ok := strings.Cut(token, "/")
		if ok && right != "" {
			if strings.Count(left, ".") == 3 {
				if _, err := strconv.Atoi(right); err == nil {
					return true
				}
			}
			if strings.Count(left, ":") >= 2 {
				if _, err := strconv.Atoi(right); err == nil {
					return true
				}
			}
		}
	}

	if strings.Count(token, ".") == 3 {
		return true
	}
	if strings.Count(token, ":") >= 2 {
		return true
	}
	return false
}

func normalizeIPs(ips []string) []string {
	var out []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		switch ip {
		case "Any IPv4", "Any IPv6", "Anywhere", "Anywhere (v6)":
			continue
		default:
			out = append(out, ip)
		}
	}
	return out
}
