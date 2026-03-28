package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
)

// Severity classifies how dangerous a detected pattern is.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// AlertType identifies the class of scam pattern detected.
type AlertType string

const (
	AlertRapidDrain       AlertType = "RAPID_DRAIN"
	AlertDustAttack       AlertType = "DUST_ATTACK"
	AlertLargeTransfer    AlertType = "LARGE_TRANSFER"
	AlertStakeChurn       AlertType = "STAKE_CHURN"
	AlertAddressPoisoning AlertType = "ADDRESS_POISONING"
)

// Alert represents a single scam-detection event.
type Alert struct {
	Timestamp   time.Time         `json:"timestamp"`
	Type        AlertType         `json:"type"`
	Severity    Severity          `json:"severity"`
	Address     string            `json:"address"`
	Description string            `json:"description"`
	TxHashes    []string          `json:"tx_hashes,omitempty"`
	BlockHeight uint64            `json:"block_height"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AlertSink handles emitting alerts to configured destinations.
type AlertSink struct {
	filePath string
}

// NewAlertSink creates a sink that prints to stdout and optionally writes JSONL to a file.
func NewAlertSink(filePath string) *AlertSink {
	return &AlertSink{filePath: filePath}
}

// Emit prints the alert to stdout and appends it to the alert file if configured.
func (s *AlertSink) Emit(alert *Alert) {
	s.printAlert(alert)
	if s.filePath != "" {
		if err := s.writeToFile(alert); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write alert to file: %v\n", err)
		}
	}
}

func (s *AlertSink) printAlert(a *Alert) {
	sevColor := color.New(color.FgWhite)
	switch a.Severity {
	case SeverityLow:
		sevColor = color.New(color.FgBlue, color.Bold)
	case SeverityMedium:
		sevColor = color.New(color.FgYellow, color.Bold)
	case SeverityHigh:
		sevColor = color.New(color.FgRed, color.Bold)
	case SeverityCritical:
		sevColor = color.New(color.FgHiRed, color.Bold)
	}

	fmt.Println("-----------------------------------------------")
	sevColor.Printf("[%s] ", a.Severity)
	color.New(color.FgCyan).Printf("[%s] ", a.Type)
	fmt.Printf("Block %d\n", a.BlockHeight)
	fmt.Printf("  Address: %s\n", a.Address)
	fmt.Printf("  %s\n", a.Description)
	if len(a.TxHashes) > 0 {
		fmt.Printf("  Transactions: %v\n", a.TxHashes)
	}
	if len(a.Metadata) > 0 {
		fmt.Printf("  Details: %v\n", a.Metadata)
	}
	fmt.Println("-----------------------------------------------")
}

func (s *AlertSink) writeToFile(alert *Alert) error {
	f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	bz, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	_, err = f.Write(append(bz, '\n'))
	return err
}
