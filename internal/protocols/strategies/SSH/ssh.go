package SSH

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type SSHStrategy struct {
	Sessions *historystore.HistoryStore
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	go sshStrategy.Sessions.HistoryCleaner()
	go func() {
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
			Handler: func(sess ssh.Session) {
				uuidSession := uuid.New()
				connID := sshConnectionID(sess.Context())

				host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				sessionKey := "SSH" + host + sess.User()
				correlationKey := tracer.SourceKey(tracer.SSH.String(), servConf.Address, host)

				// Inline SSH command
				if sess.RawCommand() != "" {
					var histories []plugins.Message
					if sshStrategy.Sessions.HasKey(sessionKey) {
						histories = sshStrategy.Sessions.Query(sessionKey)
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(sess.RawCommand()) {
							commandOutput := command.Handler
							var metadata map[string]string
							if command.Plugin != "" {
								if cp, ok := plugin.GetCommand(command.Plugin); ok {
									output, meta, err := plugins.ExecuteCommandPlugin(cp, context.Background(), plugin.CommandRequest{
										Command:  sess.RawCommand(),
										ClientIP: host,
										Protocol: "ssh",
										History:  plugins.MessagesToPlugin(histories),
										Config:   plugins.ConfigFromServiceConf(servConf),
									})
									metadata = meta
									if err != nil {
										log.Errorf("plugin %q execute error: %s", command.Plugin, err.Error())
										commandOutput = "command not found"
									} else {
										commandOutput = output
									}
								} else {
									log.Warnf("unknown plugin %q, skipping", command.Plugin)
								}
							}
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: sess.RawCommand()})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Append the new entries to the store.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)

							sess.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:            "SSH Raw Command",
								Protocol:       tracer.SSH.String(),
								RemoteAddr:     sess.RemoteAddr().String(),
								SourceIp:       host,
								SourcePort:     port,
								Status:         tracer.Start.String(),
								ID:             uuidSession.String(),
								SessionID:      connID,
								ConnID:         connID,
								CorrelationKey: correlationKey,
								Environ:        strings.Join(sess.Environ(), ","),
								User:           sess.User(),
								Description:    servConf.Description,
								Command:        sess.RawCommand(),
								CommandOutput:  commandOutput,
								Handler:        command.Name,
								Metadata:       metadata,
							})
							return
						}
					}

					// The command matched no rule: it is recorded anyway.
					// The commands an attacker types that the decoy did not
					// anticipate are the reconnaissance ones, and they are
					// the ones worth keeping.
					tr.TraceEvent(tracer.Event{
						Msg:            "SSH Raw Command",
						Protocol:       tracer.SSH.String(),
						RemoteAddr:     sess.RemoteAddr().String(),
						SourceIp:       host,
						SourcePort:     port,
						Status:         tracer.Start.String(),
						ID:             uuidSession.String(),
						SessionID:      connID,
						ConnID:         connID,
						CorrelationKey: correlationKey,
						Environ:        strings.Join(sess.Environ(), ","),
						User:           sess.User(),
						Description:    servConf.Description,
						Command:        sess.RawCommand(),
						CommandOutput:  "command not found",
						Handler:        "not_found",
					})
				}

				tr.TraceEvent(tracer.Event{
					Msg:            "New SSH Terminal Session",
					Protocol:       tracer.SSH.String(),
					RemoteAddr:     sess.RemoteAddr().String(),
					SourceIp:       host,
					SourcePort:     port,
					Status:         tracer.Start.String(),
					ID:             uuidSession.String(),
					SessionID:      connID,
					ConnID:         connID,
					CorrelationKey: correlationKey,
					Environ:        strings.Join(sess.Environ(), ","),
					User:           sess.User(),
					Description:    servConf.Description,
				})

				terminal := term.NewTerminal(sess, buildPrompt(sess.User(), servConf.ServerName))
				var histories []plugins.Message
				if sshStrategy.Sessions.HasKey(sessionKey) {
					histories = sshStrategy.Sessions.Query(sessionKey)
				}

				for {
					commandInput, err := terminal.ReadLine()
					if err != nil {
						break
					}
					if commandInput == "exit" {
						break
					}
					matched := false
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(commandInput) {
							matched = true
							commandOutput := command.Handler
							var metadata map[string]string
							if command.Plugin != "" {
								if cp, ok := plugin.GetCommand(command.Plugin); ok {
									output, meta, err := plugins.ExecuteCommandPlugin(cp, context.Background(), plugin.CommandRequest{
										Command:  commandInput,
										ClientIP: host,
										Protocol: "ssh",
										History:  plugins.MessagesToPlugin(histories),
										Config:   plugins.ConfigFromServiceConf(servConf),
									})
									metadata = meta
									if err != nil {
										log.Errorf("plugin %q execute error: %s", command.Plugin, err.Error())
										commandOutput = "command not found"
									} else {
										commandOutput = output
									}
								} else {
									log.Warnf("unknown plugin %q, skipping", command.Plugin)
								}
							}
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							sshStrategy.Sessions.Append(sessionKey, newEntries...)
							histories = append(histories, newEntries...)

							terminal.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:            "SSH Terminal Session Interaction",
								RemoteAddr:     sess.RemoteAddr().String(),
								SourceIp:       host,
								SourcePort:     port,
								Status:         tracer.Interaction.String(),
								Command:        commandInput,
								CommandOutput:  commandOutput,
								ID:             uuidSession.String(),
								SessionID:      connID,
								ConnID:         connID,
								CorrelationKey: correlationKey,
								Protocol:       tracer.SSH.String(),
								Description:    servConf.Description,
								Handler:        command.Name,
								Metadata:       metadata,
							})
							break // Inner range over commands.
						}
					}

					// The command matched no rule: it is recorded anyway.
					// A decoy that drops the commands it does not know how
					// to answer loses the evidence of the reconnaissance.
					if !matched {
						commandOutput := "command not found"
						terminal.Write([]byte(commandOutput + "\n"))

						tr.TraceEvent(tracer.Event{
							Msg:            "SSH Terminal Session Interaction",
							RemoteAddr:     sess.RemoteAddr().String(),
							SourceIp:       host,
							SourcePort:     port,
							Status:         tracer.Interaction.String(),
							Command:        commandInput,
							CommandOutput:  commandOutput,
							ID:             uuidSession.String(),
							SessionID:      connID,
							ConnID:         connID,
							CorrelationKey: correlationKey,
							Protocol:       tracer.SSH.String(),
							Description:    servConf.Description,
							Handler:        "not_found",
						})
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:            "End SSH Session",
					Status:         tracer.End.String(),
					ID:             uuidSession.String(),
					SessionID:      connID,
					ConnID:         connID,
					CorrelationKey: correlationKey,
					Protocol:       tracer.SSH.String(),
				})
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())
				connID := sshConnectionID(ctx)
				correlationKey := tracer.SourceKey(tracer.SSH.String(), servConf.Address, host)

				tr.TraceEvent(tracer.Event{
					Msg:        "New SSH Login Attempt",
					Protocol:   tracer.SSH.String(),
					Status:     tracer.Stateless.String(),
					User:       ctx.User(),
					Password:   password,
					Client:     ctx.ClientVersion(),
					RemoteAddr: ctx.RemoteAddr().String(),
					SourceIp:   host,
					SourcePort: port,
					ID:         uuid.New().String(),
					// The transport session identifier links the credential
					// attempt to the session it may open.
					SessionID:      connID,
					ConnID:         connID,
					CorrelationKey: correlationKey,
					Description:    servConf.Description,
				})
				matched, err := regexp.MatchString(servConf.PasswordRegex, password)
				if err != nil {
					log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		err := server.ListenAndServe()
		if err != nil {
			log.Errorf("error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("GetInstance service %s", servConf.Protocol)
	return nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}

// sshConnectionID returns a stable identifier for the SSH transport
// connection.
//
// The identifier is derived from the SSH session identifier negotiated during
// the key exchange, so it is the same value in the credential callback and in
// the session handler. That is what allows a login attempt to be correlated
// with the session it opens.
func sshConnectionID(ctx ssh.Context) string {
	if ctx == nil {
		return uuid.New().String()
	}
	if id := ctx.SessionID(); id != "" {
		return id
	}
	return uuid.New().String()
}
