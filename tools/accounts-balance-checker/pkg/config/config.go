package config

type Config struct {
	Elasticsearch struct {
		URL string `json:"url"`
	} `json:"elasticsearch"`
	Proxy struct {
		URL                         string `json:"url"`
		MaxNumberOfParallelRequests int    `json:"parallel-requests"`
	} `json:"proxy"`
}
