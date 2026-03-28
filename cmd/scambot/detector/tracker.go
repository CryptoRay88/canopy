package detector

import (
	"sync"
	"time"
)

// sendRecord tracks a single outbound send from an address.
type sendRecord struct {
	Recipient string
	Amount    uint64
	TxHash    string
	Timestamp time.Time
	Height    uint64
}

// addressTracker maintains per-address transaction history for pattern detection.
type addressTracker struct {
	mu       sync.Mutex
	sends    map[string][]sendRecord // sender -> list of recent sends
	receives map[string][]sendRecord // recipient -> list of recent receives
	stakes   map[string][]stakeRecord
}

type stakeRecord struct {
	Amount    uint64
	IsStake   bool // true = stake, false = unstake
	Timestamp time.Time
	Height    uint64
	TxHash    string
}

func newAddressTracker() *addressTracker {
	return &addressTracker{
		sends:    make(map[string][]sendRecord),
		receives: make(map[string][]sendRecord),
		stakes:   make(map[string][]stakeRecord),
	}
}

// RecordSend adds a send transaction to the tracker.
func (t *addressTracker) RecordSend(sender, recipient string, amount uint64, txHash string, height uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := sendRecord{
		Recipient: recipient,
		Amount:    amount,
		TxHash:    txHash,
		Timestamp: time.Now(),
		Height:    height,
	}
	t.sends[sender] = append(t.sends[sender], rec)
	t.receives[recipient] = append(t.receives[recipient], sendRecord{
		Recipient: sender, // store the sender as "Recipient" for receives
		Amount:    amount,
		TxHash:    txHash,
		Timestamp: time.Now(),
		Height:    height,
	})
}

// RecordStake adds a stake or unstake event to the tracker.
func (t *addressTracker) RecordStake(address string, amount uint64, isStake bool, txHash string, height uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stakes[address] = append(t.stakes[address], stakeRecord{
		Amount:    amount,
		IsStake:   isStake,
		Timestamp: time.Now(),
		Height:    height,
		TxHash:    txHash,
	})
}

// GetRecentSends returns sends from an address within the given window.
func (t *addressTracker) GetRecentSends(sender string, window time.Duration) []sendRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-window)
	var result []sendRecord
	for _, s := range t.sends[sender] {
		if s.Timestamp.After(cutoff) {
			result = append(result, s)
		}
	}
	return result
}

// GetRecentStakes returns stake events for an address within the given window.
func (t *addressTracker) GetRecentStakes(address string, window time.Duration) []stakeRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-window)
	var result []stakeRecord
	for _, s := range t.stakes[address] {
		if s.Timestamp.After(cutoff) {
			result = append(result, s)
		}
	}
	return result
}

// Prune removes records older than maxAge to prevent memory leaks.
func (t *addressTracker) Prune(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)

	for addr, records := range t.sends {
		var kept []sendRecord
		for _, r := range records {
			if r.Timestamp.After(cutoff) {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(t.sends, addr)
		} else {
			t.sends[addr] = kept
		}
	}

	for addr, records := range t.receives {
		var kept []sendRecord
		for _, r := range records {
			if r.Timestamp.After(cutoff) {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(t.receives, addr)
		} else {
			t.receives[addr] = kept
		}
	}

	for addr, records := range t.stakes {
		var kept []stakeRecord
		for _, r := range records {
			if r.Timestamp.After(cutoff) {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(t.stakes, addr)
		} else {
			t.stakes[addr] = kept
		}
	}
}
