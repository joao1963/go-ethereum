package main

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/log"
)

// fetcher fetches data from the remote CL, and feeds it to the EL sink.
type fetcher struct {
	cl      *remoteCL
	sink    catalyst.API
	wg      sync.WaitGroup
	closeCh chan bool
	finalCh chan beacon.ExecutableDataV1
	headCh  chan beacon.ExecutableDataV1
}

func newFetcher(config CLConfig, sink catalyst.API) (*fetcher, error) {
	cl, err := newRemoteCL(config.Address, config.Name, config.Headers)
	if err != nil {
		return nil, err
	}
	return &fetcher{
		cl:      cl,
		sink:    sink,
		closeCh: make(chan bool),
		finalCh: make(chan beacon.ExecutableDataV1, 10),
		headCh:  make(chan beacon.ExecutableDataV1, 10),
	}, nil
}

func (f *fetcher) Start() {
	f.wg.Add(2)
	go f.fetchLoop()
	go f.deliverLoop()
}

func (f *fetcher) Stop() {
	close(f.closeCh)
	f.wg.Wait()
}

// loop runs the fetcher loop, which fetches new heads and finalized blocks
// from the CL node, and emits them over the finalCh and headCh.
func (f *fetcher) fetchLoop() {
	defer f.wg.Done()
	timer := time.NewTimer(10 * time.Second)
	var final, head beacon.ExecutableDataV1

	for {
		newFinal, err := f.cl.GetFinalizedBlock()
		if err != nil {
			log.Error("Failed fetching finalized", "err", err)
		}
		if newFinal.Number != 0 && newFinal.Number != final.Number {
			final = newFinal // New finalized
			log.Info("New final block", "number", final.Number, "hash", final.BlockHash)
			select {
			case f.finalCh <- final:
			default:
			}
		}

		newHead, err := f.cl.GetHeadBlock()
		if err != nil {
			log.Error("Failed fetching head", "err", err)
		}
		if newHead.Number != 0 && newHead.Number != head.Number {
			head = newHead // New head
			log.Info("New head block", "number", head.Number, "hash", head.BlockHash)
			select {
			case f.headCh <- head:
			default:
			}
		}
		select {
		case <-timer.C:
			timer.Reset(10 + time.Second)
		case <-f.closeCh:
			return
		}
	}
}

func (f *fetcher) deliverLoop() {
	defer f.wg.Done()
	for {
		select {
		case head := <-f.headCh:
			f.sink.NewPayloadV1(head)
		case finalized := <-f.finalCh:
			f.sink.ForkchoiceUpdatedV1(beacon.ForkchoiceStateV1{
				FinalizedBlockHash: finalized.BlockHash,
			}, nil)
		case <-f.closeCh:
			return
		}
	}
}
