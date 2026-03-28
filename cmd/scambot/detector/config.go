package detector

import "time"

// Config holds tunable parameters for the scam detection bot.
type Config struct {
	// RPCURL is the Canopy node RPC endpoint.
	RPCURL string
	// PollInterval controls how frequently new blocks are polled.
	PollInterval time.Duration
	// AlertFilePath is an optional JSONL file for persisting alerts.
	AlertFilePath string

	// --- Rapid-drain detector ---
	// RapidDrainTxCount is the minimum number of outbound send transactions
	// from a single address within RapidDrainWindow to trigger an alert.
	RapidDrainTxCount int
	// RapidDrainWindow is the sliding time window for rapid-drain detection.
	RapidDrainWindow time.Duration

	// --- Dust-attack detector ---
	// DustThreshold is the maximum amount (in base units) below which a
	// send transaction is classified as "dust".
	DustThreshold uint64
	// DustTargetCount is the minimum number of unique recipients of dust
	// sends from one address to trigger an alert.
	DustTargetCount int

	// --- Large-transfer detector ---
	// LargeTransferPercent is the percentage of an account's balance that,
	// when transferred in a single send, triggers a suspicious-transfer alert.
	LargeTransferPercent float64
}

// DefaultConfig returns sensible defaults for local development.
func DefaultConfig() *Config {
	return &Config{
		RPCURL:               "http://localhost:50832",
		PollInterval:         5 * time.Second,
		RapidDrainTxCount:    5,
		RapidDrainWindow:     10 * time.Minute,
		DustThreshold:        100,
		DustTargetCount:      10,
		LargeTransferPercent: 50.0,
	}
}
