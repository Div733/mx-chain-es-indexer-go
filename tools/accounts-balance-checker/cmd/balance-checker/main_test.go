package main

import (
	"testing"

	"github.com/multiversx/mx-chain-es-indexer-go/tools/accounts-balance-checker/pkg/config"
)

func TestApplyEnvironmentOverrides(t *testing.T) {
	t.Setenv("BALANCE_CHECKER_ES_URL", "https://es.example")
	t.Setenv("BALANCE_CHECKER_ES_USERNAME", "elastic-user")
	t.Setenv("BALANCE_CHECKER_ES_PASSWORD", "elastic-password")
	t.Setenv("BALANCE_CHECKER_PROXY_URL", "https://proxy.example")

	cfg := &config.Config{}
	applyEnvironmentOverrides(cfg)

	if cfg.Elasticsearch.URL != "https://es.example" {
		t.Fatalf("unexpected elasticsearch url %q", cfg.Elasticsearch.URL)
	}
	if cfg.Elasticsearch.Username != "elastic-user" {
		t.Fatalf("unexpected elasticsearch username %q", cfg.Elasticsearch.Username)
	}
	if cfg.Elasticsearch.Password != "elastic-password" {
		t.Fatalf("unexpected elasticsearch password %q", cfg.Elasticsearch.Password)
	}
	if cfg.Proxy.URL != "https://proxy.example" {
		t.Fatalf("unexpected proxy url %q", cfg.Proxy.URL)
	}
}
