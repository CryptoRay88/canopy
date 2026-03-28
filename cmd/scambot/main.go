package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canopy-network/canopy/cmd/scambot/detector"
	"github.com/fatih/color"
)

func main() {
	rpcURL := flag.String("rpc", "http://localhost:50832", "Canopy RPC endpoint URL")
	pollInterval := flag.Duration("poll", 5*time.Second, "Block polling interval")
	alertFile := flag.String("alerts", "", "Path to write JSON alerts (default: stdout only)")
	rapidDrainTxCount := flag.Int("rapid-drain-tx", 5, "Min outbound txs to flag rapid drain")
	rapidDrainWindow := flag.Duration("rapid-drain-window", 10*time.Minute, "Time window for rapid drain detection")
	dustThreshold := flag.Uint64("dust-threshold", 100, "Amount below which a send is considered dust")
	dustTargetCount := flag.Int("dust-targets", 10, "Min unique recipients to flag a dust attack")
	largeTransferPct := flag.Float64("large-transfer-pct", 50.0, "% of account balance to flag as large transfer")
	flag.Parse()

	printBanner()

	cfg := &detector.Config{
		RPCURL:               *rpcURL,
		PollInterval:         *pollInterval,
		AlertFilePath:        *alertFile,
		RapidDrainTxCount:    *rapidDrainTxCount,
		RapidDrainWindow:     *rapidDrainWindow,
		DustThreshold:        *dustThreshold,
		DustTargetCount:      *dustTargetCount,
		LargeTransferPercent: *largeTransferPct,
	}

	bot, err := detector.NewScamBot(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize scambot: %v\n", err)
		os.Exit(1)
	}

	// handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nshutting down scambot...")
		bot.Stop()
	}()

	fmt.Printf("scambot connected to %s — polling every %s\n", *rpcURL, *pollInterval)
	bot.Run()
}

func printBanner() {
	bold := color.New(color.Bold, color.FgCyan)
	bold.Print(`
   ____                      ____        _
  / ___|  ___ __ _ _ __ ___ | __ )  ___ | |_
  \___ \ / __/ _' | '_ ' _ \|  _ \ / _ \| __|
   ___) | (_| (_| | | | | | | |_) | (_) | |_
  |____/ \___\__,_|_| |_| |_|____/ \___/ \__|

  Canopy Wallet Scam Detector
`)
	fmt.Println()
}
