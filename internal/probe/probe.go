package probe

import (
	"context"
	"encoding/binary"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/gabspt/ConnectionStats/internal/timer"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats.c - -O3  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10 // 10MB

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

type Flowrecord struct {
	fid probeFlowId
	fm  probeFlowMetrics
}

func setRlimit() error {
	log.Println("Setting rlimit")

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: tenMegaBytes,
	})
}

func (p *probe) loadObjects() error {
	log.Printf("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	log.Printf("Creating qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	log.Printf("Creating qdisc filters")

	addFilterin := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsin.FD(),
			DirectAction: true,
		})
	}
	addFilterout := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsout.FD(),
			DirectAction: true,
		})
	}

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterout(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	addFilterout(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	log.Println("Creating a new probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prbe, nil
}

// func print global metrics
func (p *probe) PrintGlobalMetrics() {
	globalmetricsmap := p.bpfObjects.probeMaps.Globalmetrics
	keyg := uint32(0)
	var gm probeGlobalMetrics
	err := globalmetricsmap.Lookup(keyg, &gm)
	if err != nil {
		log.Fatalf("Failed to lookup global metrics: %v", err)
	}

	log.Printf("")
	log.Printf("Global metrics:")
	log.Printf("---------------")
	log.Printf("Total packets analyzed: %v", gm.TotalPackets)
	log.Printf("Total TCP packets analyzed: %v", gm.TotalTcppackets)
	log.Printf("Total UDP packets analyzed: %v", gm.TotalUdppackets)
	log.Printf("Total flows analyzed: %v", gm.TotalFlows)
	log.Printf("Total TCP flows analyzed: %v", gm.TotalTcpflows)
	log.Printf("Total UDP flows analyzed: %v", gm.TotalUdpflows)
	log.Printf("")
}

func (p *probe) Close() error {

	p.PrintGlobalMetrics()

	log.Println("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		log.Println("Failed deleting qdisc")
		return err
	}

	log.Println("Deleting handle")
	p.handle.Delete()

	log.Println("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	return nil
}

func UnmarshalFlowRecord(in []byte) (Flowrecord, bool) {
	//gather bits from []byte to form L_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var l_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		l_ip.In6U.U6Addr8[i] = in[i]
	}
	//gather bits from []byte to form R_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var r_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		r_ip.In6U.U6Addr8[i] = in[i+16]
	}

	// form the probeFlowId struct
	f_id := probeFlowId{
		L_ip:     l_ip,
		R_ip:     r_ip,
		L_port:   binary.BigEndian.Uint16(in[32:34]),
		R_port:   binary.BigEndian.Uint16(in[34:36]),
		Protocol: in[36],
	}

	// form the probeFlowMetrics struct
	f_m := probeFlowMetrics{
		PacketsIn:    binary.LittleEndian.Uint32(in[40:44]),
		PacketsOut:   binary.LittleEndian.Uint32(in[44:48]),
		BytesIn:      binary.LittleEndian.Uint64(in[48:56]),
		BytesOut:     binary.LittleEndian.Uint64(in[56:64]),
		TsStart:      binary.LittleEndian.Uint64(in[64:72]),
		TsCurrent:    binary.LittleEndian.Uint64(in[72:80]),
		FinCounter:   in[80],
		FlowClosed:   in[81] == 1,
		SynToRingbuf: in[82] == 1,
	}
	//log.Printf("Binary: L_ip %v R_ip %v L_port %v R_port %v Protocol %v", in[0:16], in[16:32], in[32:34], in[34:36], in[36])
	//log.Printf("Binary: PacketsIn %v PacketsOut %v BytesIn %v BytesOut %v TsStart %v TsCurrent %v Fin %v", in[37:41], in[41:45], in[45:53], in[53:61], in[61:69], in[69:77], in[77])

	return Flowrecord{
		fid: f_id,
		fm:  f_m,
	}, true
}

// Prune deletes stale entries (havnt been updated in more than 60 seconds = 60000ms) directly from the hash map Flowstracker
// For testing pruposes we will adjust the Prune IDLE_TIMEOUT according to the defaults timeouts used in tstat tool
func (p *probe) Prune(ft *FlowTable) {

	flowstrackermap := p.bpfObjects.probeMaps.Flowstracker
	iterator := flowstrackermap.Iterate()
	var fid probeFlowId
	var flowmetrics probeFlowMetrics
	for iterator.Next(&fid, &flowmetrics) {
		if (flowmetrics.PacketsIn + flowmetrics.PacketsOut) > 2 {
			if fid.Protocol == 6 { //TCP
				lastts := flowmetrics.TsCurrent
				now := timer.GetNanosecSinceBoot()
				if (now-lastts)/1000000 > 300000 { //300000ms = 5min
					log.Printf("Pruning stale entry from flowstracker map: %v with tscurr %v at %vtime after %vms", fid, lastts, now, (now-lastts)/1000000)
					flowstrackermap.Delete(&fid)
					//Delete also from the flowtable
					ft.Remove(fid)
				}
			} else if fid.Protocol == 17 { //UDP
				lastts := flowmetrics.TsCurrent
				now := timer.GetNanosecSinceBoot()
				if (now-lastts)/1000000 > 200000 { //200000ms = 3min and 20s
					log.Printf("Pruning stale entry from flowstracker map: %v with tscurr %v at %vtime after %vms", fid, lastts, now, (now-lastts)/1000000)
					flowstrackermap.Delete(&fid)
					//Delete also from the flowtable
					ft.Remove(fid)
				}
			}
		} else {
			//no packets have been observed for this flow 10 seconds after the initial packet,
			lastts := flowmetrics.TsCurrent
			now := timer.GetNanosecSinceBoot()
			if (now-lastts)/1000000 > 10000 { //10000ms = 10s
				log.Printf("Pruning stale entry from flowstracker map: %v with tscurr %v at %vtime after %vms", fid, lastts, now, (now-lastts)/1000000)
				flowstrackermap.Delete(&fid)
				//Delete also from the flowtable
				ft.Remove(fid)
			}
		}
	}
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, ft *FlowTable) error {
	log.Println("Starting up the probe")

	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker

	//evict all entries from the flowstracker map and copy to the flowtable every 5 seconds
	tickerevict := time.NewTicker(time.Second * 5)
	defer tickerevict.Stop()
	//revisar esta go routine, a ver si la tengo que hacer con el mismo estilo de select que la de Prune
	go func() {
		for range tickerevict.C {
			//cuando yo haga el evict cada 5s no puedo simplemente dumpear el hash map ahi sin ver lo que habia
			//porque el flowtable tiene flows que vinieron por el ringbuf y no entraron al hasmap,
			//entonces tengo que chequear si el flow ya esta en el flowtable y si es asi actualizarlo, cogiendo el tstart mas antiguo y tcurrent mas reciente y sumando los paquetes y bytes
			//flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker
			iterator := flowstrackermap.Iterate()
			var fid probeFlowId
			var flowmetrics probeFlowMetrics
			//iterate over the hash map flowstrackermap
			for iterator.Next(&fid, &flowmetrics) {
				//lookup if flow id exists in the flowtable ft and update accordingly
				//if true to UpdateFlowTable (FlowTable updated successfully), delete packets and bytes metrics from flowstrackermap
				updated := ft.UpdateFlowTable(fid, flowmetrics)
				if updated {
					flowmetrics.PacketsIn = 0
					flowmetrics.PacketsOut = 0
					flowmetrics.BytesIn = 0
					flowmetrics.BytesOut = 0
					flowstrackermap.Update(&fid, &flowmetrics, ebpf.UpdateExist)
				}
			}
			log.Printf("FlowTable size: %v\n", ft.Size())

			log.Printf(" ")
		}
	}()

	pipe := probe.bpfObjects.probeMaps.Pipe
	ringreader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Println("Failed creating ringbuf reader")
		return err
	}

	//revisar esta go routine, a ver si la tengo que hacer con el mismo estilo de select que la de Prune
	go func() {
		for {
			event, err := ringreader.Read()
			if err != nil {
				log.Printf("Failed reading ringbuf event: %v", err)
				return
			}
			//log.Printf("Pkt received from ringbuf: %+v", event.RawSample)
			flowrecord, ok := UnmarshalFlowRecord(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall flow record: %+v", event.RawSample)
				continue
			}
			log.Printf("Flowrecord unmarshalled: %+v", flowrecord)

			// if flow record fin is true, delete from flow table
			if flowrecord.fm.FlowClosed {
				ft.Remove(flowrecord.fid)
			} else {
				ft.UpdateFlowTableFromRingbuf(flowrecord.fid, flowrecord.fm)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				probe.Prune(ft)
			}
		}
	}()

	for {

		<-ctx.Done()

		ft.Ticker.Stop()
		tickerevict.Stop()
		return probe.Close()

	}
}
