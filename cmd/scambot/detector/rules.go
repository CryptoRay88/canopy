package detector

import (
	"fmt"
	"strconv"
	"time"
)

// Rule is a detection heuristic that inspects tracked data and emits alerts.
type Rule interface {
	// Name returns a human-readable identifier for the rule.
	Name() string
	// Evaluate checks the tracker state after new transactions are ingested
	// and returns any alerts.
	Evaluate(tracker *addressTracker, height uint64, cfg *Config) []*Alert
}

// --- Rapid Drain Rule ---

// RapidDrainRule flags addresses that send many outbound transactions in a
// short window, a common pattern when a compromised wallet is being emptied.
type RapidDrainRule struct {
	// alerted tracks addresses already flagged to avoid duplicate alerts.
	alerted map[string]time.Time
}

func NewRapidDrainRule() *RapidDrainRule {
	return &RapidDrainRule{alerted: make(map[string]time.Time)}
}

func (r *RapidDrainRule) Name() string { return "RapidDrain" }

func (r *RapidDrainRule) Evaluate(tracker *addressTracker, height uint64, cfg *Config) []*Alert {
	var alerts []*Alert
	tracker.mu.Lock()
	senders := make([]string, 0, len(tracker.sends))
	for addr := range tracker.sends {
		senders = append(senders, addr)
	}
	tracker.mu.Unlock()

	for _, sender := range senders {
		recent := tracker.GetRecentSends(sender, cfg.RapidDrainWindow)
		if len(recent) < cfg.RapidDrainTxCount {
			continue
		}
		// skip if already alerted recently
		if lastAlert, ok := r.alerted[sender]; ok && time.Since(lastAlert) < cfg.RapidDrainWindow {
			continue
		}
		// collect unique recipients and total amount
		recipients := make(map[string]struct{})
		var totalAmount uint64
		var hashes []string
		for _, rec := range recent {
			recipients[rec.Recipient] = struct{}{}
			totalAmount += rec.Amount
			hashes = append(hashes, rec.TxHash)
		}

		r.alerted[sender] = time.Now()
		alerts = append(alerts, &Alert{
			Timestamp:   time.Now(),
			Type:        AlertRapidDrain,
			Severity:    SeverityHigh,
			Address:     sender,
			Description: fmt.Sprintf("%d outbound sends totaling %d tokens to %d recipients in %s — possible wallet drain", len(recent), totalAmount, len(recipients), cfg.RapidDrainWindow),
			TxHashes:    hashes,
			BlockHeight: height,
			Metadata: map[string]string{
				"tx_count":        strconv.Itoa(len(recent)),
				"total_amount":    strconv.FormatUint(totalAmount, 10),
				"unique_targets":  strconv.Itoa(len(recipients)),
				"window_duration": cfg.RapidDrainWindow.String(),
			},
		})
	}
	return alerts
}

// --- Dust Attack Rule ---

// DustAttackRule detects addresses sending tiny amounts to many unique
// recipients. Attackers use this to pollute transaction histories so victims
// accidentally copy a scam address.
type DustAttackRule struct {
	alerted map[string]time.Time
}

func NewDustAttackRule() *DustAttackRule {
	return &DustAttackRule{alerted: make(map[string]time.Time)}
}

func (r *DustAttackRule) Name() string { return "DustAttack" }

func (r *DustAttackRule) Evaluate(tracker *addressTracker, height uint64, cfg *Config) []*Alert {
	var alerts []*Alert
	tracker.mu.Lock()
	senders := make([]string, 0, len(tracker.sends))
	for addr := range tracker.sends {
		senders = append(senders, addr)
	}
	tracker.mu.Unlock()

	window := cfg.RapidDrainWindow // reuse same window
	for _, sender := range senders {
		if lastAlert, ok := r.alerted[sender]; ok && time.Since(lastAlert) < window {
			continue
		}
		recent := tracker.GetRecentSends(sender, window)
		// count dust sends and unique recipients
		recipients := make(map[string]struct{})
		var dustCount int
		var hashes []string
		for _, rec := range recent {
			if rec.Amount <= cfg.DustThreshold {
				dustCount++
				recipients[rec.Recipient] = struct{}{}
				hashes = append(hashes, rec.TxHash)
			}
		}
		if dustCount == 0 || len(recipients) < cfg.DustTargetCount {
			continue
		}

		r.alerted[sender] = time.Now()
		alerts = append(alerts, &Alert{
			Timestamp:   time.Now(),
			Type:        AlertDustAttack,
			Severity:    SeverityMedium,
			Address:     sender,
			Description: fmt.Sprintf("%d dust sends (amount <= %d) to %d unique addresses — possible address-poisoning dust attack", dustCount, cfg.DustThreshold, len(recipients)),
			TxHashes:    hashes,
			BlockHeight: height,
			Metadata: map[string]string{
				"dust_tx_count":  strconv.Itoa(dustCount),
				"dust_threshold": strconv.FormatUint(cfg.DustThreshold, 10),
				"unique_targets": strconv.Itoa(len(recipients)),
			},
		})
	}
	return alerts
}

// --- Stake Churn Rule ---

// StakeChurnRule flags addresses that rapidly stake and then unstake, which
// can indicate a validator gaming rewards or manipulating committee membership.
type StakeChurnRule struct {
	alerted map[string]time.Time
}

func NewStakeChurnRule() *StakeChurnRule {
	return &StakeChurnRule{alerted: make(map[string]time.Time)}
}

func (r *StakeChurnRule) Name() string { return "StakeChurn" }

func (r *StakeChurnRule) Evaluate(tracker *addressTracker, height uint64, cfg *Config) []*Alert {
	var alerts []*Alert
	tracker.mu.Lock()
	addrs := make([]string, 0, len(tracker.stakes))
	for addr := range tracker.stakes {
		addrs = append(addrs, addr)
	}
	tracker.mu.Unlock()

	window := cfg.RapidDrainWindow
	for _, addr := range addrs {
		if lastAlert, ok := r.alerted[addr]; ok && time.Since(lastAlert) < window {
			continue
		}
		recent := tracker.GetRecentStakes(addr, window)
		var stakeCount, unstakeCount int
		var hashes []string
		for _, rec := range recent {
			if rec.IsStake {
				stakeCount++
			} else {
				unstakeCount++
			}
			hashes = append(hashes, rec.TxHash)
		}
		// flag if both stake and unstake happened within the window
		if stakeCount >= 1 && unstakeCount >= 1 {
			r.alerted[addr] = time.Now()
			alerts = append(alerts, &Alert{
				Timestamp:   time.Now(),
				Type:        AlertStakeChurn,
				Severity:    SeverityMedium,
				Address:     addr,
				Description: fmt.Sprintf("%d stakes and %d unstakes within %s — possible stake-churn manipulation", stakeCount, unstakeCount, window),
				TxHashes:    hashes,
				BlockHeight: height,
				Metadata: map[string]string{
					"stake_count":   strconv.Itoa(stakeCount),
					"unstake_count": strconv.Itoa(unstakeCount),
				},
			})
		}
	}
	return alerts
}

// --- Large Transfer Rule ---

// LargeTransferRule flags single send transactions that move a large
// proportion of an address's balance, often a sign of account compromise.
type LargeTransferRule struct{}

func NewLargeTransferRule() *LargeTransferRule { return &LargeTransferRule{} }

func (r *LargeTransferRule) Name() string { return "LargeTransfer" }

// EvaluateSingle is called per-transaction rather than in batch to check
// the sender's balance at the time of the send.
func (r *LargeTransferRule) EvaluateSingle(sender string, amount, senderBalance uint64, txHash string, height uint64, cfg *Config) *Alert {
	if senderBalance == 0 {
		return nil
	}
	pct := float64(amount) / float64(senderBalance) * 100
	if pct < cfg.LargeTransferPercent {
		return nil
	}

	severity := SeverityMedium
	if pct >= 90 {
		severity = SeverityCritical
	} else if pct >= 75 {
		severity = SeverityHigh
	}

	return &Alert{
		Timestamp:   time.Now(),
		Type:        AlertLargeTransfer,
		Severity:    severity,
		Address:     sender,
		Description: fmt.Sprintf("single send of %d tokens (%.1f%% of balance %d) — possible account compromise", amount, pct, senderBalance),
		TxHashes:    []string{txHash},
		BlockHeight: height,
		Metadata: map[string]string{
			"amount":          strconv.FormatUint(amount, 10),
			"sender_balance":  strconv.FormatUint(senderBalance, 10),
			"balance_percent": fmt.Sprintf("%.1f", pct),
		},
	}
}

// Evaluate satisfies the Rule interface but large-transfer checks happen
// per-transaction via EvaluateSingle, so this is a no-op.
func (r *LargeTransferRule) Evaluate(_ *addressTracker, _ uint64, _ *Config) []*Alert {
	return nil
}

// --- Address Poisoning Rule ---

// AddressPoisoningRule detects sends from addresses that share a prefix or
// suffix with addresses the recipient has previously interacted with. Scammers
// create look-alike addresses hoping victims will copy-paste the wrong one.
type AddressPoisoningRule struct {
	alerted map[string]time.Time
}

func NewAddressPoisoningRule() *AddressPoisoningRule {
	return &AddressPoisoningRule{alerted: make(map[string]time.Time)}
}

func (r *AddressPoisoningRule) Name() string { return "AddressPoisoning" }

func (r *AddressPoisoningRule) Evaluate(tracker *addressTracker, height uint64, cfg *Config) []*Alert {
	return nil // per-transaction checks happen in EvaluateSend
}

// EvaluateSend checks whether a sender address visually resembles any address
// the recipient has previously transacted with.
func (r *AddressPoisoningRule) EvaluateSend(sender, recipient string, amount uint64, txHash string, height uint64, tracker *addressTracker, cfg *Config) *Alert {
	if amount > cfg.DustThreshold {
		return nil // only check dust-sized sends for poisoning
	}
	key := sender + ":" + recipient
	if lastAlert, ok := r.alerted[key]; ok && time.Since(lastAlert) < cfg.RapidDrainWindow {
		return nil
	}
	// get addresses the recipient has previously sent to
	tracker.mu.Lock()
	prevSends := tracker.sends[recipient]
	tracker.mu.Unlock()

	for _, prev := range prevSends {
		if prev.Recipient == sender {
			continue // same address, not spoofing
		}
		if looksLike(sender, prev.Recipient) {
			r.alerted[key] = time.Now()
			return &Alert{
				Timestamp:   time.Now(),
				Type:        AlertAddressPoisoning,
				Severity:    SeverityHigh,
				Address:     sender,
				Description: fmt.Sprintf("dust send from %s resembles known contact %s of recipient %s — possible address poisoning", truncAddr(sender), truncAddr(prev.Recipient), truncAddr(recipient)),
				TxHashes:    []string{txHash},
				BlockHeight: height,
				Metadata: map[string]string{
					"spoofed_address": prev.Recipient,
					"recipient":       recipient,
					"amount":          strconv.FormatUint(amount, 10),
				},
			}
		}
	}
	return nil
}

// looksLike returns true if two hex addresses share the first or last 4 characters.
func looksLike(a, b string) bool {
	if len(a) < 8 || len(b) < 8 {
		return false
	}
	prefixMatch := a[:4] == b[:4]
	suffixMatch := a[len(a)-4:] == b[len(b)-4:]
	return prefixMatch && suffixMatch
}

// truncAddr returns a shortened version of an address for display.
func truncAddr(addr string) string {
	if len(addr) <= 12 {
		return addr
	}
	return addr[:6] + "..." + addr[len(addr)-4:]
}
