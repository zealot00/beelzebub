package HTTP

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type HTTPStrategy struct{}

type httpResponse struct {
	StatusCode int
	Headers    []string
	Body       string
}

func (httpStrategy HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	serverMux := http.NewServeMux()

	serverMux.HandleFunc("/", newHTTPHandler(servConf, tr))
	go func() {
		var err error
		// The timeouts bound the resources a single connection can hold: a
		// slow client must not be able to keep a handler, and its memory,
		// alive indefinitely. Without them a handful of stalled connections
		// would degrade the decoy.
		server := &http.Server{
			Addr:              servConf.Address,
			Handler:           serverMux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		// Launch a TLS supporting server if we are supplied a TLS Key and Certificate.
		// If relative paths are supplied, they are relative to the CWD of the binary.
		// The can be self-signed, only the client will validate this (or not).
		if servConf.TLSKeyPath != "" && servConf.TLSCertPath != "" {
			err = server.ListenAndServeTLS(servConf.TLSCertPath, servConf.TLSKeyPath)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil {
			log.Errorf("error during init HTTP Protocol: %v", err)
			return
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("Init service: %s", servConf.Description)
	return nil
}

func newHTTPHandler(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		var resp httpResponse
		var err error
		command, allowedMethods := matchHTTPCommand(servConf.Commands, request)
		if command != nil {
			resp, err = buildHTTPResponse(servConf, tr, *command, request)
			if err != nil {
				log.Errorf("error building http response: %s: %v", request.RequestURI, err)
				resp.StatusCode = 500
				resp.Body = "500 Internal Server Error"
			}
		} else if len(allowedMethods) > 0 {
			resp.StatusCode = http.StatusMethodNotAllowed
			resp.Headers = []string{"Allow:" + strings.Join(allowedMethods, ", ")}
			resp.Body = http.StatusText(http.StatusMethodNotAllowed)
			traceRequest(request, tr, parser.Command{}, servConf, "", servConf.TrustedProxiesNets, nil, "")
		} else {
			// If none of the main commands matched, and we have a fallback command configured, process it here.
			// The regexp is ignored for fallback commands, as they are catch-all for any request.
			command := servConf.FallbackCommand
			if command.Handler != "" || command.Plugin != "" {
				resp, err = buildHTTPResponse(servConf, tr, command, request)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					resp.StatusCode = 500
					resp.Body = "500 Internal Server Error"
				}
			}
		}
		setResponseHeaders(responseWriter, resp.Headers, resp.StatusCode)
		fmt.Fprint(responseWriter, resp.Body)
	}
}

func matchHTTPCommand(commands []parser.Command, request *http.Request) (*parser.Command, []string) {
	var allowedMethods []string
	for i := range commands {
		command := &commands[i]
		if !command.Regex.MatchString(request.RequestURI) {
			continue
		}
		if len(command.Methods) == 0 || slices.Contains(command.Methods, request.Method) {
			return command, nil
		}
		for _, method := range command.Methods {
			if !slices.Contains(allowedMethods, method) {
				allowedMethods = append(allowedMethods, method)
			}
		}
	}
	return nil, allowedMethods
}

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request) (httpResponse, error) {
	resp := httpResponse{
		Body: command.Handler,
		// The header slice belongs to the service configuration, which is
		// shared by every request: it must not be appended to in place.
		Headers:    slices.Clone(command.Headers),
		StatusCode: command.StatusCode,
	}

	// Limit body read to 1MB to prevent DoS attacks
	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, 1024*1024))
	body := ""
	if err == nil {
		body = string(bodyBytes)
	}

	// The event is emitted after the plugin answered, so that it can carry
	// the response and the plugin findings. It is emitted in every case: a
	// failing plugin must not lose the interaction.
	var metadata map[string]string
	var pluginErr error

	if command.Plugin != "" {
		host, _ := realClientAddr(request, servConf.TrustedProxiesNets)

		if cp, ok := plugin.GetCommand(command.Plugin); ok {
			cmd := fmt.Sprintf("Method: %s, RequestURI: %s, Body: %s", request.Method, request.RequestURI, body)
			output, meta, execErr := plugins.ExecuteCommandPlugin(cp, context.Background(), plugin.CommandRequest{
				Command:  cmd,
				ClientIP: host,
				Protocol: "http",
				Config:   plugins.ConfigFromServiceConf(servConf),
			})
			metadata = meta
			if execErr != nil {
				resp.Body = "404 Not Found!"
				pluginErr = fmt.Errorf("plugin %q execute error: %w", command.Plugin, execErr)
			} else {
				resp.Body = output
			}
		} else if hp, ok := plugin.GetHTTP(command.Plugin); ok {
			// For HTTP-specific plugins (e.g. MazeHoneypot) that need full
			// request context and return their own status/headers.
			// ServerVersion and ServerName are injected here from service config.
			if command.Plugin == plugins.MazePluginName {
				maze := &plugins.MazeHoneypot{
					ServerVersion: servConf.ServerVersion,
					ServerName:    servConf.ServerName,
				}
				mazeResp := maze.HandleRequest(request)
				resp.StatusCode = mazeResp.StatusCode
				resp.Body = mazeResp.Body
				for k, v := range mazeResp.Headers {
					resp.Headers = append(resp.Headers, fmt.Sprintf("%s: %s", k, v))
				}
				resp.Headers = append(resp.Headers, fmt.Sprintf("Content-Type: %s", mazeResp.ContentType))
			} else {
				httpResp := hp.HandleHTTP(request)
				resp.StatusCode = httpResp.StatusCode
				resp.Body = httpResp.Body
				resp.Headers = append(resp.Headers, fmt.Sprintf("Content-Type: %s", httpResp.ContentType))
				for k, v := range httpResp.Headers {
					resp.Headers = append(resp.Headers, fmt.Sprintf("%s: %s", k, v))
				}
			}
		} else {
			log.Warnf("unknown plugin %q, skipping", command.Plugin)
		}
	}

	traceRequest(request, tr, command, servConf, body, servConf.TrustedProxiesNets, metadata, resp.Body)

	if pluginErr != nil {
		return resp, pluginErr
	}

	return resp, nil
}

func traceRequest(request *http.Request, tr tracer.Tracer, command parser.Command, servConf parser.BeelzebubServiceConfiguration, body string, trustedProxies []*net.IPNet, metadata map[string]string, commandOutput string) {
	host, port := realClientAddr(request, trustedProxies)

	remoteAddr := host
	if port != "" {
		remoteAddr = net.JoinHostPort(host, port)
	}
	event := tracer.Event{
		Msg:             "HTTP New request",
		RequestURI:      request.RequestURI,
		Protocol:        tracer.HTTP.String(),
		HTTPMethod:      request.Method,
		Body:            body,
		HostHTTPRequest: request.Host,
		UserAgent:       request.UserAgent(),
		Cookies:         mapCookiesToString(request.Cookies()),
		Headers:         mapHeaderToString(request.Header),
		// The header map is copied: the request owns it, and the event is
		// dispatched asynchronously.
		HeadersMap:  cloneHeaderMap(request.Header),
		Status:      tracer.Stateless.String(),
		RemoteAddr:  remoteAddr,
		SourceIp:    host,
		SourcePort:  port,
		ID:          uuid.New().String(),
		Description: servConf.Description,
		Handler:     command.Name,
		// HTTP has no transport session to hang an identifier on, so the
		// source carries one: requests coming from the same peer inside the
		// session window share a SessionID and a CorrelationKey.
		SessionID:      tracer.SourceSession(tracer.HTTP.String(), host),
		CorrelationKey: tracer.SourceKey(tracer.HTTP.String(), servConf.Address, host),
		CommandOutput:  commandOutput,
		Metadata:       metadata,
	}
	// Capture the TLS details from the request, if provided.
	if request.TLS != nil {
		event.Msg = "HTTPS New Request"
		event.TLSServerName = request.TLS.ServerName
	}
	tr.TraceEvent(event)
}

// realClientAddr returns the host and port of the real client.
//
// The immediate TCP peer (request.RemoteAddr) is the only non-spoofable source
// of identity: it is set by Go's net/http server from the socket peer address.
// X-Forwarded-For and X-Real-IP are application-level headers and trivially
// forgeable when the honeypot is reachable directly from the Internet.
//
// Algorithm:
//   - If trustedProxies is empty OR the immediate peer is not in trustedProxies,
//     headers are ignored entirely and the peer address is returned. This
//     protects deployments where beelzebub is exposed directly: an attacker
//     setting "X-Forwarded-For: 8.8.8.8" cannot make us log 8.8.8.8.
//   - If the peer is a trusted proxy, X-Forwarded-For is parsed right-to-left
//     and the first entry that is NOT itself a trusted hop is treated as the
//     real client. This neutralizes XFF poisoning, where a client sends a
//     pre-filled XFF and the trusted proxy appends the real peer to it
//     ("spoofed, real-peer"): walking from the right skips the trusted hops
//     until the legitimate client IP appears.
//   - If XFF is empty or contains only trusted hops, X-Real-IP is consulted as
//     a single-hop fallback. If it too is missing or trusted, the peer
//     address is returned.
//
// The returned port mirrors the peer's port; XFF/X-Real-IP do not carry port
// information, so when the address comes from a header the port is empty.
func realClientAddr(r *http.Request, trustedProxies []*net.IPNet) (host, port string) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
		port = ""
	}
	if len(trustedProxies) == 0 {
		return host, port
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil || !ipInNets(peerIP, trustedProxies) {
		return host, port
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !ipInNets(ip, trustedProxies) {
				return candidate, ""
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil && !ipInNets(ip, trustedProxies) {
			return xri, ""
		}
	}
	return host, port
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// cloneHeaderMap copies the header map of a request.
//
// The event outlives the handler, so it must not keep a reference to the
// map owned by the request.
func cloneHeaderMap(headers http.Header) map[string][]string {
	if headers == nil {
		return nil
	}

	clone := make(map[string][]string, len(headers))
	for key, values := range headers {
		copied := make([]string, len(values))
		copy(copied, values)
		clone[key] = copied
	}

	return clone
}

func mapHeaderToString(headers http.Header) string {
	headersString := ""

	for key := range headers {
		for _, values := range headers[key] {
			headersString += fmt.Sprintf("[Key: %s, values: %s],", key, values)
		}
	}

	return headersString
}

func mapCookiesToString(cookies []*http.Cookie) string {
	cookiesString := ""

	for _, cookie := range cookies {
		cookiesString += cookie.String()
	}

	return cookiesString
}

func setResponseHeaders(responseWriter http.ResponseWriter, headers []string, statusCode int) {
	for _, headerStr := range headers {
		keyValue := strings.Split(headerStr, ":")
		if len(keyValue) > 1 {
			responseWriter.Header().Add(keyValue[0], keyValue[1])
		}
	}
	// http.StatusText(statusCode): empty string if the code is unknown.
	if len(http.StatusText(statusCode)) > 0 {
		responseWriter.WriteHeader(statusCode)
	}
}
