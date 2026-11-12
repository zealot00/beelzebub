package plugins

import (
	"context"
	"fmt"

	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
)

// llmPlugin is the registry adapter for LLMHoneypot.
// It bridges the pkg/plugin.CommandPlugin interface to the internal LLMHoneypot implementation.
type llmPlugin struct{}

func (l *llmPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        LLMPluginName,
		Description: "LLM-powered response generator — emulates realistic system behaviour via OpenAI or Ollama",
		Version:     "1.0.0",
		Author:      "beelzebub",
	}
}

func (l *llmPlugin) Execute(ctx context.Context, req plugin.CommandRequest) (string, error) {
	output, _, err := l.ExecuteWithMetadata(ctx, req)
	return output, err
}

// ExecuteWithMetadata returns the generated response together with the
// guardrail findings.
//
// The findings describe what the guardrails did — an injection attempt, a
// truncated input, a redacted credential, a replaced refusal — and are the
// signal that tells an analyst the decoy was driven by an AI agent rather
// than by a human.
func (l *llmPlugin) ExecuteWithMetadata(ctx context.Context, req plugin.CommandRequest) (string, map[string]string, error) {
	llmProvider, err := FromStringToLLMProvider(req.Config.LLMProvider)
	if err != nil {
		return "", nil, fmt.Errorf("llm plugin: %w", err)
	}

	proto, ok := tracer.ProtocolFromString(req.Protocol)
	if !ok {
		return "", nil, fmt.Errorf("llm plugin: unknown protocol %q", req.Protocol)
	}

	hp := &LLMHoneypot{
		Histories:               MessagesFromPlugin(req.History),
		OpenAIKey:               req.Config.OpenAISecretKey,
		Protocol:                proto,
		Host:                    req.Config.Host,
		Model:                   req.Config.LLMModel,
		Provider:                llmProvider,
		CustomPrompt:            req.Config.Prompt,
		InputValidationEnabled:  req.Config.InputValidationEnabled,
		InputValidationPrompt:   req.Config.InputValidationPrompt,
		OutputValidationEnabled: req.Config.OutputValidationEnabled,
		OutputValidationPrompt:  req.Config.OutputValidationPrompt,
		RateLimitEnabled:        req.Config.RateLimitEnabled,
		RateLimitRequests:       req.Config.RateLimitRequests,
		RateLimitWindowSeconds:  req.Config.RateLimitWindowSeconds,
		MaxInputLength:          req.Config.MaxInputLength,
		MaxOutputLength:         req.Config.MaxOutputLength,
		RedactCredentials:       !req.Config.CredentialRedactionDisabled,
	}

	// The instance returned by InitLLMHoneypot is the one that holds the
	// findings: InitLLMHoneypot takes the configuration by value, so the
	// state recorded during the call belongs to the returned instance.
	instance := InitLLMHoneypot(*hp)

	response, err := instance.ExecuteModel(req.Command, req.ClientIP)
	metadata := instance.EventMetadata()

	if err != nil {
		return "", metadata, err
	}

	return response, metadata, nil
}

func init() {
	plugin.Register(&llmPlugin{})
}
