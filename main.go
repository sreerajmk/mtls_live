package main

import (
	"bufio"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"
)

const maxEvents = 5000

//go:embed public/*
var publicFiles embed.FS

type Event struct {
	ID        string      `json:"id"`
	SessionID string      `json:"sessionId"`
	Timestamp time.Time   `json:"timestamp"`
	Packet    int         `json:"packetNumber"`
	Type      string      `json:"type"`
	Label     string      `json:"label"`
	Direction string      `json:"direction"`
	Summary   string      `json:"summary"`
	Detail    string      `json:"detail,omitempty"`
	Encrypted bool        `json:"encrypted,omitempty"`
	Content   interface{} `json:"content,omitempty"`
}

type Trigger struct {
	Method          string            `json:"method"`
	Route           string            `json:"route"`
	RequestID       string            `json:"requestId"`
	TraceID         string            `json:"traceId,omitempty"`
	StartedAt       time.Time         `json:"startedAt"`
	Destination     string            `json:"destination,omitempty"`
	RedactedHeaders map[string]string `json:"redactedHeaders,omitempty"`
}

type Session struct {
	mu            sync.RWMutex
	ID            string
	Mode          string
	Interface     string
	BPF           string
	Status        string
	StartedAt     time.Time
	Trigger       *Trigger
	Events        []Event
	FirstObserved string
	Clients       map[chan Event]struct{}
	Process       *exec.Cmd
}

type sessionSummary struct {
	ID            string    `json:"id"`
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"startedAt"`
	Trigger       *Trigger  `json:"trigger"`
	EventCount    int       `json:"eventCount"`
	FirstObserved string    `json:"firstObserved,omitempty"`
}

type sessionResponse struct {
	sessionSummary
	Events []Event `json:"events,omitempty"`
}

type createRequest struct {
	Mode      string   `json:"mode"`
	Interface string   `json:"interface"`
	BPF       string   `json:"bpf"`
	Trigger   *Trigger `json:"trigger"`
}

var sessions = struct {
	sync.RWMutex
	items map[string]*Session
}{items: make(map[string]*Session)}

var demoEvents = []struct{ typ, label, direction, summary, detail string }{
	{"dns", "DNS query", "client", "api.example.test -> A api.example.test", "name=api.example.test"},
	{"dns", "DNS response", "server", "api.example.test -> 10.20.0.15", "ttl=60"},
	{"tcp", "TCP SYN", "client", "10.20.0.8:53124 -> 10.20.0.15:443", "flags=SYN"},
	{"tcp", "TCP SYN/ACK", "server", "10.20.0.15:443 -> 10.20.0.8:53124", "flags=SYN,ACK"},
	{"tcp", "TCP ACK", "client", "10.20.0.8:53124 -> 10.20.0.15:443", "flags=ACK"},
	{"tls", "ClientHello", "client", "TLS 1.3", "sni=api.example.test alpn=h2"},
	{"tls", "ServerHello", "server", "TLS 1.3", "cipher=TLS_AES_256_GCM_SHA384"},
	{"tls", "Certificate", "server", "server certificate", "subject=api.example.test issuer=Example Intermediate"},
	{"tls", "CertificateRequest", "server", "client authentication requested", "signature_algorithms=ECDSA+SHA256,RSA-PSS+SHA256"},
	{"tls", "Certificate", "client", "client certificate", "subject=service-client issuer=Example Client CA"},
	{"tls", "CertificateVerify", "client", "client proof of possession", "signature=ECDSA"},
	{"tls", "Finished", "server", "handshake complete", ""},
	{"tls", "Finished", "client", "handshake complete", ""},
	{"record", "Application Data", "client", "encrypted TLS record", "content=unavailable_without_keylog"},
	{"record", "Application Data", "server", "encrypted TLS record", "content=unavailable_without_keylog"},
}

func newID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func newSession(input createRequest) *Session {
	mode := input.Mode
	if mode == "" {
		mode = "demo"
	}
	iface := input.Interface
	if iface == "" {
		iface = os.Getenv("CAPTURE_INTERFACE")
	}
	if iface == "" {
		iface = defaultCaptureInterface()
	}
	bpf := input.BPF
	if bpf == "" {
		bpf = "tcp port 443 or port 53"
	}
	session := &Session{ID: newID(), Mode: mode, Interface: iface, BPF: bpf, Status: "starting", StartedAt: time.Now().UTC(), Clients: make(map[chan Event]struct{})}
	sessions.Lock()
	sessions.items[session.ID] = session
	sessions.Unlock()
	return session
}

func defaultCaptureInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return iface.Name
		}
	}
	return ""
}

func summary(session *Session) sessionSummary {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return sessionSummary{ID: session.ID, Mode: session.Mode, Status: session.Status, StartedAt: session.StartedAt, Trigger: session.Trigger, EventCount: len(session.Events), FirstObserved: session.FirstObserved}
}

func snapshot(session *Session) sessionResponse {
	session.mu.RLock()
	defer session.mu.RUnlock()
	events := append([]Event(nil), session.Events...)
	return sessionResponse{sessionSummary: sessionSummary{ID: session.ID, Mode: session.Mode, Status: session.Status, StartedAt: session.StartedAt, Trigger: session.Trigger, EventCount: len(events), FirstObserved: session.FirstObserved}, Events: events}
}

func publish(session *Session, input Event) {
	session.mu.Lock()
	input.ID, input.SessionID, input.Timestamp, input.Packet = newID(), session.ID, time.Now().UTC(), len(session.Events)+1
	if session.FirstObserved == "" && input.Type != "api" && input.Type != "system" {
		if input.Type == "dns" {
			session.FirstObserved = "DNS"
		} else if input.Type == "tcp" && input.Label == "TCP SYN" {
			session.FirstObserved = "TCP SYN"
		} else {
			session.FirstObserved = input.Label
		}
	}
	session.Events = append(session.Events, input)
	if len(session.Events) > maxEvents {
		session.Events = session.Events[len(session.Events)-maxEvents:]
	}
	clients := make([]chan Event, 0, len(session.Clients))
	for client := range session.Clients {
		clients = append(clients, client)
	}
	session.mu.Unlock()
	for _, client := range clients {
		select {
		case client <- input:
		default:
		}
	}
}

func attachTrigger(session *Session, input Trigger) {
	if input.Method == "" {
		input.Method = "GET"
	}
	if input.Route == "" {
		input.Route = "/"
	}
	if input.RequestID == "" {
		input.RequestID = newID()
	}
	if input.StartedAt.IsZero() {
		input.StartedAt = time.Now().UTC()
	}
	session.mu.Lock()
	session.Trigger = &input
	session.mu.Unlock()
	publish(session, Event{Type: "api", Label: "API trigger", Direction: "client", Summary: input.Method + " " + input.Route, Detail: mustJSON(input)})
}

func startDemo(session *Session) {
	session.mu.Lock()
	session.Status = "live"
	session.mu.Unlock()
	go func() {
		for index, item := range demoEvents {
			session.mu.RLock()
			stopped := session.Status == "stopped"
			session.mu.RUnlock()
			if stopped {
				return
			}
			publish(session, Event{Type: item.typ, Label: item.label, Direction: item.direction, Summary: item.summary, Detail: item.detail, Encrypted: item.typ == "record"})
			if index < 4 {
				time.Sleep(160 * time.Millisecond)
			} else {
				time.Sleep(260 * time.Millisecond)
			}
		}
		session.mu.Lock()
		if session.Status == "live" {
			session.Status = "complete"
		}
		session.mu.Unlock()
	}()
}

func startLive(session *Session) {
	if session.Interface == "" {
		session.mu.Lock()
		session.Status = "error"
		session.mu.Unlock()
		publish(session, Event{Type: "system", Label: "Capture error", Direction: "system", Summary: "No capture interface configured", Detail: "Set CAPTURE_INTERFACE or provide interface in POST /api/sessions."})
		return
	}
	cmd := exec.Command("tshark", "-i", session.Interface, "-l", "-T", "ek", "-f", session.BPF)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		captureError(session, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		captureError(session, err)
		return
	}
	if err := cmd.Start(); err != nil {
		captureError(session, err)
		return
	}
	session.mu.Lock()
	session.Status = "live"
	session.Process = cmd
	session.mu.Unlock()
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			parseTshark(session, scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text != "" {
				publish(session, Event{Type: "system", Label: "Capture notice", Direction: "system", Summary: trim(text, 240), Detail: "tshark stderr"})
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		session.mu.Lock()
		if session.Status == "live" {
			if err == nil {
				session.Status = "complete"
			} else {
				session.Status = "error"
			}
		}
		session.mu.Unlock()
	}()
}

func captureError(session *Session, err error) {
	session.mu.Lock()
	session.Status = "error"
	session.mu.Unlock()
	publish(session, Event{Type: "system", Label: "Capture unavailable", Direction: "system", Summary: err.Error(), Detail: "Install tshark and grant the capture process appropriate permissions."})
}

func parseTshark(session *Session, line string) {
	var packet map[string]interface{}
	if json.Unmarshal([]byte(line), &packet) != nil {
		return
	}
	layers, _ := packet["layers"].(map[string]interface{})
	if layers == nil {
		if source, ok := packet["_source"].(map[string]interface{}); ok {
			layers, _ = source["layers"].(map[string]interface{})
		}
	}
	if layers == nil {
		return
	}
	typ, label := "packet", "Packet"
	if _, ok := layers["dns"]; ok {
		typ, label = "dns", "DNS"
	}
	if tcp, ok := layers["tcp"].(map[string]interface{}); ok {
		flags := fmt.Sprint(tcp["tcp.flags.str"], tcp["tcp.flags"])
		if strings.Contains(flags, "SYN") {
			typ = "tcp"
			if strings.Contains(flags, "ACK") {
				label = "TCP SYN/ACK"
			} else {
				label = "TCP SYN"
			}
		}
	}
	if _, ok := layers["tls"]; ok {
		typ, label = "tls", "TLS record"
	}
	publish(session, Event{Type: typ, Label: label, Direction: "client", Summary: "captured packet", Detail: mustJSON(layers), Encrypted: typ == "tls"})
}

func mustJSON(value interface{}) string { bytes, _ := json.Marshal(value); return string(bytes) }
func trim(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length]
}

func decodeBody(request *http.Request, target interface{}) error {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	return decoder.Decode(target)
}
func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-cache")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func getSession(id string) (*Session, bool) {
	sessions.RLock()
	session, ok := sessions.items[id]
	sessions.RUnlock()
	return session, ok
}

func sessionsHandler(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		sessions.RLock()
		result := make([]sessionSummary, 0, len(sessions.items))
		for _, session := range sessions.items {
			result = append(result, summary(session))
		}
		sessions.RUnlock()
		writeJSON(response, http.StatusOK, result)
		return
	}
	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input createRequest
	if err := decodeBody(request, &input); err != nil && err != io.EOF {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	session := newSession(input)
	if input.Trigger != nil {
		attachTrigger(session, *input.Trigger)
	}
	if session.Mode == "live" {
		startLive(session)
	} else {
		startDemo(session)
	}
	writeJSON(response, http.StatusCreated, summary(session))
}

func sessionHandler(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(path.Clean(request.URL.Path), "/api/sessions/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(response, request)
		return
	}
	session, ok := getSession(parts[0])
	if !ok {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "":
		if request.Method != http.MethodGet {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(response, http.StatusOK, snapshot(session))
	case "trigger":
		var trigger Trigger
		if err := decodeBody(request, &trigger); err != nil {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		attachTrigger(session, trigger)
		writeJSON(response, http.StatusOK, summary(session))
	case "stop":
		session.mu.Lock()
		session.Status = "stopped"
		process := session.Process
		session.mu.Unlock()
		if process != nil {
			_ = process.Process.Kill()
		}
		publish(session, Event{Type: "system", Label: "Capture stopped", Direction: "system", Summary: "Capture stopped by operator"})
		writeJSON(response, http.StatusOK, summary(session))
	case "export":
		writeJSON(response, http.StatusOK, snapshot(session))
	case "stream":
		streamSession(response, request, session)
	default:
		http.NotFound(response, request)
	}
}

func streamSession(response http.ResponseWriter, request *http.Request, session *Session) {
	flusher, ok := response.(http.Flusher)
	if !ok {
		http.Error(response, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	response.Header().Set("Cache-Control", "no-cache")
	response.Header().Set("Connection", "keep-alive")
	client := make(chan Event, 32)
	snapshotBytes, _ := json.Marshal(snapshot(session))
	session.mu.Lock()
	session.Clients[client] = struct{}{}
	session.mu.Unlock()
	defer func() { session.mu.Lock(); delete(session.Clients, client); close(client); session.mu.Unlock() }()
	fmt.Fprintf(response, "event: snapshot\ndata: %s\n\n", snapshotBytes)
	flusher.Flush()
	notifier := request.Context().Done()
	for {
		select {
		case event := <-client:
			bytes, _ := json.Marshal(event)
			fmt.Fprintf(response, "data: %s\n\n", bytes)
			flusher.Flush()
		case <-notifier:
			return
		}
	}
}

func choosePort(requested string) string {
	if requested == "" {
		requested = "8787"
	}
	for _, candidate := range []string{requested, "8787", "8788", "8789", "8790"} {
		listener, err := net.Listen("tcp", ":"+candidate)
		if err == nil {
			_ = listener.Close()
			return candidate
		}
	}
	return requested
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}
	port = choosePort(port)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", sessionsHandler)
	mux.HandleFunc("/api/sessions/", sessionHandler)
	mux.Handle("/", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		name := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		data, err := publicFiles.ReadFile("public/" + name)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		contentType := "text/html; charset=utf-8"
		if strings.HasSuffix(name, ".css") {
			contentType = "text/css; charset=utf-8"
		} else if strings.HasSuffix(name, ".js") {
			contentType = "text/javascript; charset=utf-8"
		}
		response.Header().Set("Content-Type", contentType)
		_, _ = response.Write(data)
	}))
	server := &http.Server{Addr: ":" + port, Handler: logging(mux)}
	log.Printf("mTLS Live Dashboard listening on http://localhost:%s", port)
	log.Fatal(server.ListenAndServe())
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { next.ServeHTTP(response, request) })
}
