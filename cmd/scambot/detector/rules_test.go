package detector

import (
	"testing"
	"time"
)

func TestRapidDrainRule(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewRapidDrainRule()
	cfg := DefaultConfig()
	cfg.RapidDrainTxCount = 3
	cfg.RapidDrainWindow = 1 * time.Minute

	// add 3 sends from the same address within the window
	tracker.RecordSend("sender1", "recv1", 1000, "tx1", 100)
	tracker.RecordSend("sender1", "recv2", 2000, "tx2", 100)
	tracker.RecordSend("sender1", "recv3", 3000, "tx3", 100)

	alerts := rule.Evaluate(tracker, 100, cfg)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 rapid-drain alert, got %d", len(alerts))
	}
	if alerts[0].Type != AlertRapidDrain {
		t.Errorf("expected alert type %s, got %s", AlertRapidDrain, alerts[0].Type)
	}
	if alerts[0].Severity != SeverityHigh {
		t.Errorf("expected severity %s, got %s", SeverityHigh, alerts[0].Severity)
	}
	if alerts[0].Address != "sender1" {
		t.Errorf("expected address sender1, got %s", alerts[0].Address)
	}
}

func TestRapidDrainRule_BelowThreshold(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewRapidDrainRule()
	cfg := DefaultConfig()
	cfg.RapidDrainTxCount = 5

	// only 2 sends — should not trigger
	tracker.RecordSend("sender1", "recv1", 1000, "tx1", 100)
	tracker.RecordSend("sender1", "recv2", 2000, "tx2", 100)

	alerts := rule.Evaluate(tracker, 100, cfg)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestRapidDrainRule_NoDuplicateAlert(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewRapidDrainRule()
	cfg := DefaultConfig()
	cfg.RapidDrainTxCount = 2
	cfg.RapidDrainWindow = 1 * time.Minute

	tracker.RecordSend("sender1", "recv1", 1000, "tx1", 100)
	tracker.RecordSend("sender1", "recv2", 2000, "tx2", 100)

	alerts := rule.Evaluate(tracker, 100, cfg)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert on first eval, got %d", len(alerts))
	}

	// second evaluation should not produce duplicate
	alerts = rule.Evaluate(tracker, 101, cfg)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts on second eval (already alerted), got %d", len(alerts))
	}
}

func TestDustAttackRule(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewDustAttackRule()
	cfg := DefaultConfig()
	cfg.DustThreshold = 100
	cfg.DustTargetCount = 3
	cfg.RapidDrainWindow = 1 * time.Minute

	// send dust to 3 unique recipients
	tracker.RecordSend("attacker", "victim1", 10, "tx1", 200)
	tracker.RecordSend("attacker", "victim2", 20, "tx2", 200)
	tracker.RecordSend("attacker", "victim3", 5, "tx3", 200)

	alerts := rule.Evaluate(tracker, 200, cfg)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 dust-attack alert, got %d", len(alerts))
	}
	if alerts[0].Type != AlertDustAttack {
		t.Errorf("expected alert type %s, got %s", AlertDustAttack, alerts[0].Type)
	}
}

func TestDustAttackRule_NotEnoughTargets(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewDustAttackRule()
	cfg := DefaultConfig()
	cfg.DustThreshold = 100
	cfg.DustTargetCount = 10

	// only 2 recipients — should not trigger
	tracker.RecordSend("attacker", "victim1", 10, "tx1", 200)
	tracker.RecordSend("attacker", "victim2", 20, "tx2", 200)

	alerts := rule.Evaluate(tracker, 200, cfg)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestStakeChurnRule(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewStakeChurnRule()
	cfg := DefaultConfig()
	cfg.RapidDrainWindow = 1 * time.Minute

	tracker.RecordStake("val1", 50000, true, "tx1", 300)
	tracker.RecordStake("val1", 0, false, "tx2", 305)

	alerts := rule.Evaluate(tracker, 305, cfg)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 stake-churn alert, got %d", len(alerts))
	}
	if alerts[0].Type != AlertStakeChurn {
		t.Errorf("expected alert type %s, got %s", AlertStakeChurn, alerts[0].Type)
	}
}

func TestStakeChurnRule_StakeOnly(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewStakeChurnRule()
	cfg := DefaultConfig()
	cfg.RapidDrainWindow = 1 * time.Minute

	// only stake, no unstake — should not trigger
	tracker.RecordStake("val1", 50000, true, "tx1", 300)

	alerts := rule.Evaluate(tracker, 300, cfg)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestLargeTransferRule(t *testing.T) {
	rule := NewLargeTransferRule()
	cfg := DefaultConfig()
	cfg.LargeTransferPercent = 50.0

	// transfer 80% of balance
	alert := rule.EvaluateSingle("addr1", 8000, 10000, "tx1", 400, cfg)
	if alert == nil {
		t.Fatal("expected large-transfer alert, got nil")
	}
	if alert.Type != AlertLargeTransfer {
		t.Errorf("expected alert type %s, got %s", AlertLargeTransfer, alert.Type)
	}
	if alert.Severity != SeverityHigh {
		t.Errorf("expected severity HIGH for 80%%, got %s", alert.Severity)
	}
}

func TestLargeTransferRule_Critical(t *testing.T) {
	rule := NewLargeTransferRule()
	cfg := DefaultConfig()
	cfg.LargeTransferPercent = 50.0

	// transfer 95% of balance
	alert := rule.EvaluateSingle("addr1", 9500, 10000, "tx1", 400, cfg)
	if alert == nil {
		t.Fatal("expected large-transfer alert, got nil")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected severity CRITICAL for 95%%, got %s", alert.Severity)
	}
}

func TestLargeTransferRule_BelowThreshold(t *testing.T) {
	rule := NewLargeTransferRule()
	cfg := DefaultConfig()
	cfg.LargeTransferPercent = 50.0

	// transfer only 10% of balance
	alert := rule.EvaluateSingle("addr1", 1000, 10000, "tx1", 400, cfg)
	if alert != nil {
		t.Fatal("expected no alert for small transfer, got one")
	}
}

func TestAddressPoisoningRule(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewAddressPoisoningRule()
	cfg := DefaultConfig()
	cfg.DustThreshold = 100
	cfg.RapidDrainWindow = 1 * time.Minute

	// victim previously sent to a known address
	tracker.RecordSend("victim1", "abcd1234real5678wxyz", 5000, "tx0", 500)

	// attacker sends dust from a look-alike address (same first 4 + last 4 chars)
	alert := rule.EvaluateSend("abcdfake0000fakewxyz", "victim1", 1, "tx1", 510, tracker, cfg)
	if alert == nil {
		t.Fatal("expected address-poisoning alert, got nil")
	}
	if alert.Type != AlertAddressPoisoning {
		t.Errorf("expected alert type %s, got %s", AlertAddressPoisoning, alert.Type)
	}
}

func TestAddressPoisoningRule_NoMatchNoAlert(t *testing.T) {
	tracker := newAddressTracker()
	rule := NewAddressPoisoningRule()
	cfg := DefaultConfig()
	cfg.DustThreshold = 100
	cfg.RapidDrainWindow = 1 * time.Minute

	// victim previously sent to a known address
	tracker.RecordSend("victim1", "abcd1234real5678wxyz", 5000, "tx0", 500)

	// attacker sends dust but address doesn't match
	alert := rule.EvaluateSend("zzzz0000differentaaa", "victim1", 1, "tx1", 510, tracker, cfg)
	if alert != nil {
		t.Fatal("expected no alert for non-matching address, got one")
	}
}

func TestLooksLike(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abcd1234real5678wxyz", "abcdfake0000fakewxyz", true},  // same prefix and suffix
		{"abcd1234real5678wxyz", "xxxx1234real5678wxyz", false}, // different prefix
		{"abcd1234real5678wxyz", "abcd1234real5678xxxx", false}, // different suffix
		{"abcd1234real5678wxyz", "abcd1234real5678wxyz", true},  // identical
		{"short", "short", false},                               // too short
	}
	for _, tt := range tests {
		got := looksLike(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("looksLike(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestTrackerPrune(t *testing.T) {
	tracker := newAddressTracker()
	tracker.RecordSend("a", "b", 100, "tx1", 1)

	// prune with zero duration should remove everything
	tracker.Prune(0)

	tracker.mu.Lock()
	sendCount := len(tracker.sends["a"])
	tracker.mu.Unlock()

	if sendCount != 0 {
		t.Errorf("expected 0 sends after prune, got %d", sendCount)
	}
}
