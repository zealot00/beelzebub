package plugins

import (
	"context"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
)

// MessagesToPlugin converts internal plugin.Message slice to pkg/plugin format.
func MessagesToPlugin(messages []Message) []plugin.Message {
	result := make([]plugin.Message, len(messages))
	for i, m := range messages {
		result[i] = plugin.Message{Role: m.Role, Content: m.Content}
	}
	return result
}

// MessagesFromPlugin converts pkg/plugin messages to the internal format.
func MessagesFromPlugin(messages []plugin.Message) []Message {
	result := make([]Message, len(messages))
	for i, m := range messages {
		result[i] = Message{Role: m.Role, Content: m.Content}
	}
	return result
}

// ConfigFromServiceConf builds a plugin.Config from a service configuration.
func ConfigFromServiceConf(servConf parser.BeelzebubServiceConfiguration) plugin.Config {
	return plugin.Config{
		LLMProvider:                 servConf.Plugin.LLMProvider,
		LLMModel:                    servConf.Plugin.LLMModel,
		OpenAISecretKey:             servConf.Plugin.OpenAISecretKey,
		Host:                        servConf.Plugin.Host,
		Prompt:                      servConf.Plugin.Prompt,
		InputValidationEnabled:      servConf.Plugin.InputValidationEnabled,
		InputValidationPrompt:       servConf.Plugin.InputValidationPrompt,
		OutputValidationEnabled:     servConf.Plugin.OutputValidationEnabled,
		OutputValidationPrompt:      servConf.Plugin.OutputValidationPrompt,
		RateLimitEnabled:            servConf.Plugin.RateLimitEnabled,
		RateLimitRequests:           servConf.Plugin.RateLimitRequests,
		RateLimitWindowSeconds:      servConf.Plugin.RateLimitWindowSeconds,
		MaxInputLength:              servConf.Plugin.MaxInputLength,
		MaxOutputLength:             servConf.Plugin.MaxOutputLength,
		CredentialRedactionDisabled: servConf.Plugin.CredentialRedactionDisabled,
		ServerVersion:               servConf.ServerVersion,
		ServerName:                  servConf.ServerName,
	}
}

// ExecuteCommandPlugin runs a command plugin and returns the response
// together with the metadata it contributes to the interaction event.
//
// Plugins that do not implement plugin.ResultCommandPlugin simply return no
// metadata.
func ExecuteCommandPlugin(cp plugin.CommandPlugin, ctx context.Context, req plugin.CommandRequest) (string, map[string]string, error) {
	if resultPlugin, ok := cp.(plugin.ResultCommandPlugin); ok {
		return resultPlugin.ExecuteWithMetadata(ctx, req)
	}

	output, err := cp.Execute(ctx, req)
	return output, nil, err
}
