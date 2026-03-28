package detector

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/canopy-network/canopy/cmd/rpc"
	"github.com/canopy-network/canopy/fsm"
	"github.com/canopy-network/canopy/lib"
)

// ScamBot polls a Canopy node for new blocks and runs scam-detection rules
// against the transactions it finds.
type ScamBot struct {
	cfg     *Config
	client  *rpc.Client
	tracker *addressTracker
	sink    *AlertSink
	rules   []Rule

	// per-tx rules (checked inline rather than in batch)
	largeTransferRule    *LargeTransferRule
	addressPoisoningRule *AddressPoisoningRule

	lastHeight uint64
	stopCh     chan struct{}
}

// NewScamBot creates a new bot connected to the configured RPC endpoint.
func NewScamBot(cfg *Config) (*ScamBot, error) {
	client := rpc.NewClient(cfg.RPCURL, "")
	sink := NewAlertSink(cfg.AlertFilePath)

	largeRule := NewLargeTransferRule()
	poisonRule := NewAddressPoisoningRule()

	return &ScamBot{
		cfg:     cfg,
		client:  client,
		tracker: newAddressTracker(),
		sink:    sink,
		rules: []Rule{
			NewRapidDrainRule(),
			NewDustAttackRule(),
			NewStakeChurnRule(),
			largeRule,
			poisonRule,
		},
		largeTransferRule:    largeRule,
		addressPoisoningRule: poisonRule,
		stopCh:               make(chan struct{}),
	}, nil
}

// Run starts the main polling loop. It blocks until Stop is called.
func (b *ScamBot) Run() {
	ticker := time.NewTicker(b.cfg.PollInterval)
	defer ticker.Stop()

	// prune old records every 5 minutes
	pruneTicker := time.NewTicker(5 * time.Minute)
	defer pruneTicker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-pruneTicker.C:
			b.tracker.Prune(b.cfg.RapidDrainWindow * 3)
		case <-ticker.C:
			b.poll()
		}
	}
}

// Stop signals the bot to shut down.
func (b *ScamBot) Stop() {
	close(b.stopCh)
}

func (b *ScamBot) poll() {
	heightResult, err := b.client.Height()
	if err != nil {
		fmt.Printf("rpc height error: %v\n", err)
		return
	}
	currentHeight := heightResult.Height
	if currentHeight <= b.lastHeight {
		return
	}

	// process blocks we haven't seen yet
	start := b.lastHeight + 1
	if b.lastHeight == 0 {
		// on first poll, only look at the latest block
		start = currentHeight
	}

	for h := start; h <= currentHeight; h++ {
		b.processBlock(h)
	}
	b.lastHeight = currentHeight
}

func (b *ScamBot) processBlock(height uint64) {
	page, err := b.client.TransactionsByHeight(height, lib.PageParams{PageNumber: 1, PerPage: 100})
	if err != nil {
		fmt.Printf("rpc txs-by-height error at height %d: %v\n", height, err)
		return
	}

	if page == nil {
		return
	}

	// unmarshal the results into TxResult slice
	var txResults []*lib.TxResult
	resultBytes, marshalErr := json.Marshal(page.Results)
	if marshalErr != nil {
		fmt.Printf("marshal page results error at height %d: %v\n", height, marshalErr)
		return
	}
	if unmarshalErr := json.Unmarshal(resultBytes, &txResults); unmarshalErr != nil {
		fmt.Printf("unmarshal tx results error at height %d: %v\n", height, unmarshalErr)
		return
	}

	for _, txResult := range txResults {
		b.processTx(txResult, height)
	}

	// run batch rules after processing all txs in the block
	for _, rule := range b.rules {
		for _, alert := range rule.Evaluate(b.tracker, height, b.cfg) {
			b.sink.Emit(alert)
		}
	}
}

// extractSendAmount extracts the token amount from a send transaction's message payload.
func extractSendAmount(tx *lib.Transaction) uint64 {
	if tx == nil || tx.Msg == nil {
		return 0
	}
	protoMsg, err := lib.FromAny(tx.Msg)
	if err != nil {
		return 0
	}
	if msg, ok := protoMsg.(*fsm.MessageSend); ok {
		return msg.Amount
	}
	return 0
}

// extractStakeAmount extracts the token amount from a stake transaction's message payload.
func extractStakeAmount(tx *lib.Transaction) uint64 {
	if tx == nil || tx.Msg == nil {
		return 0
	}
	protoMsg, err := lib.FromAny(tx.Msg)
	if err != nil {
		return 0
	}
	switch msg := protoMsg.(type) {
	case *fsm.MessageStake:
		return msg.Amount
	case *fsm.MessageEditStake:
		return msg.Amount
	}
	return 0
}

func (b *ScamBot) processTx(txResult *lib.TxResult, height uint64) {
	if txResult == nil || txResult.Transaction == nil {
		return
	}

	sender := lib.BytesToString(txResult.Sender)
	recipient := lib.BytesToString(txResult.Recipient)
	txHash := txResult.TxHash

	switch txResult.MessageType {
	case "send":
		amount := extractSendAmount(txResult.Transaction)

		b.tracker.RecordSend(sender, recipient, amount, txHash, height)

		// per-tx: large transfer check
		balance, balErr := b.getBalance(sender)
		if balErr == nil {
			// use balance + amount as an estimate of pre-tx balance
			preTxBalance := balance + amount
			if alert := b.largeTransferRule.EvaluateSingle(sender, amount, preTxBalance, txHash, height, b.cfg); alert != nil {
				b.sink.Emit(alert)
			}
		}

		// per-tx: address poisoning check
		if alert := b.addressPoisoningRule.EvaluateSend(sender, recipient, amount, txHash, height, b.tracker, b.cfg); alert != nil {
			b.sink.Emit(alert)
		}

	case "stake":
		amount := extractStakeAmount(txResult.Transaction)
		b.tracker.RecordStake(sender, amount, true, txHash, height)

	case "unstake":
		b.tracker.RecordStake(sender, 0, false, txHash, height)
	}
}

func (b *ScamBot) getBalance(address string) (uint64, error) {
	account, err := b.client.Account(0, address)
	if err != nil {
		return 0, fmt.Errorf("rpc account error: %v", err)
	}
	if account == nil {
		return 0, fmt.Errorf("account not found")
	}
	return account.Amount, nil
}
