package main

import "C"

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf trace_net.bpf.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	_, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// SEC("tp/net/net_dev_queue")
	if tp, err := link.Tracepoint("net", "net_dev_queue", objs.HandleNetDevQueue, nil); err != nil {
		log.Printf("Failed to attach to tracepoint(net_dev_queue): %v", err)
		return
	} else {
		log.Printf("Attached to tracepoint(net_dev_queue)")
		defer tp.Close()
	}

	// <-ctx.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		log.Printf("net_dev_queue called %s times\n", objs.bpfMaps)
	}
}
