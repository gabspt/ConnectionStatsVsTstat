package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats_tcpreplay_forensic_simple.c - -O3  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10      // 10MB
const twentyMegaBytes = tenMegaBytes * 2   // 20MB
const fortyMegaBytes = twentyMegaBytes * 2 // 40MB

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

type Flowrecord struct {
	fid uint64
	fm  probeFlowMetrics
}

func setRlimit() error {
	log.Printf("Setting rlimit - soft: %v, hard: %v", twentyMegaBytes, fortyMegaBytes)

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: twentyMegaBytes,
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

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
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
	log.Printf("Total packets processed: %v", gm.TotalProcessedpackets)
	log.Printf("Total packets analyzed (TCP+UDP): %v", gm.TotalTcpudppackets)
	log.Printf("Total TCP packets analyzed: %v", gm.TotalTcppackets)
	log.Printf("Total UDP packets analyzed: %v", gm.TotalUdppackets)
	log.Printf("Total flows analyzed: %v", gm.TotalFlows)
	log.Printf("Total TCP flows analyzed: %v", gm.TotalTcpflows)
	log.Printf("Total UDP flows analyzed: %v", gm.TotalUdpflows)
	log.Printf("")
}

func writeFlowStatsToFile(filename string, flowMetrics probeFlowMetrics) {
	// Open the log file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	// Write the flow stats to the log file
	if flowMetrics.FlowTuple.Protocol == 6 {
		_, err = f.WriteString(fmt.Sprintf("%v %v %v %v %v %v %v %v %v %v %v %v %v %v %v\n",
			net.IP(flowMetrics.FlowTuple.A_ip.In6U.U6Addr8[:]).String(), flowMetrics.FlowTuple.A_port, flowMetrics.PacketsOut, flowMetrics.BytesOut, flowMetrics.PayloadOut, net.IP(flowMetrics.FlowTuple.B_ip.In6U.U6Addr8[:]).String(), flowMetrics.FlowTuple.B_port, flowMetrics.PacketsIn, flowMetrics.BytesIn, flowMetrics.PayloadIn, float64(flowMetrics.TsCurrent-flowMetrics.TsStart)/1000000, flowMetrics.TsStart, flowMetrics.TsCurrent, flowMetrics.FinCounter, flowMetrics.FlowClosed))
		if err != nil {
			log.Println(err)
		}
	} else {
		_, err = f.WriteString(fmt.Sprintf("%v %v %v %v %v %v %v %v %v %v %v %v %v\n",
			net.IP(flowMetrics.FlowTuple.A_ip.In6U.U6Addr8[:]).String(), flowMetrics.FlowTuple.A_port, flowMetrics.PacketsOut, flowMetrics.BytesOut, flowMetrics.PayloadOut, net.IP(flowMetrics.FlowTuple.B_ip.In6U.U6Addr8[:]).String(), flowMetrics.FlowTuple.B_port, flowMetrics.PacketsIn, flowMetrics.BytesIn, flowMetrics.PayloadIn, float64(flowMetrics.TsCurrent-flowMetrics.TsStart)/1000000, flowMetrics.TsStart, flowMetrics.TsCurrent))
		if err != nil {
			log.Println(err)
		}
	}
}

func EvictMapEntries(flowstrackermap *ebpf.Map, ft *FlowTable) {
	iterator := flowstrackermap.Iterate()
	var flowhash uint64
	var flowmetrics probeFlowMetrics
	//iterate over the hash map flowstrackermap
	for iterator.Next(&flowhash, &flowmetrics) {
		ft.Store(flowhash, flowmetrics)
	}
}

// LogFlowTable writes all flows in the FlowTable to the log.
func LogFlowTable(ft *FlowTable) {
	ft.Range(func(key, value interface{}) bool {
		//flowId := key.(uint64)
		flowMetrics := value.(probeFlowMetrics)
		var filename string
		if flowMetrics.FlowTuple.Protocol == 6 { //TCP
			filename = "flow_tcp_nocomplete_stats.txt"
		} else {
			filename = "flow_udp_stats.txt"
		}
		writeFlowStatsToFile(filename, flowMetrics)
		return true
	})
}

func (p *probe) Close(ft *FlowTable) error {

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

	LogFlowTable(ft)

	return nil
}

func UnmarshalFlowRecord(in []byte) (Flowrecord, bool) {
	f_id := binary.LittleEndian.Uint64(in[0:8])
	//gather bits from []byte to form L_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var a_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		a_ip.In6U.U6Addr8[i] = in[i+8]
	}
	//gather bits from []byte to form R_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var b_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		b_ip.In6U.U6Addr8[i] = in[i+24]
	}
	// form the probeFlowMetrics struct
	f_m := probeFlowMetrics{
		FlowTuple: struct {
			A_ip     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			B_ip     struct{ In6U struct{ U6Addr8 [16]uint8 } }
			A_port   uint16
			B_port   uint16
			Protocol uint8
			_        [3]byte
		}{
			A_ip:     a_ip,
			B_ip:     b_ip,
			A_port:   binary.LittleEndian.Uint16(in[40:42]),
			B_port:   binary.LittleEndian.Uint16(in[42:44]),
			Protocol: in[44],
		},
		PacketsIn:    binary.LittleEndian.Uint32(in[48:52]),
		PacketsOut:   binary.LittleEndian.Uint32(in[52:56]),
		BytesIn:      binary.LittleEndian.Uint64(in[56:64]),
		PayloadIn:    binary.LittleEndian.Uint64(in[64:72]),
		BytesOut:     binary.LittleEndian.Uint64(in[72:80]),
		PayloadOut:   binary.LittleEndian.Uint64(in[80:88]),
		TsStart:      binary.LittleEndian.Uint64(in[88:96]),
		TsCurrent:    binary.LittleEndian.Uint64(in[96:104]),
		FinCounter:   in[104],
		AckCounter:   in[105],
		FlowClosed:   in[106],
		SynOrUdpToRb: in[107] == 1,
	}

	return Flowrecord{
		fid: f_id,
		fm:  f_m,
	}, true
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, ft *FlowTable) error {
	log.Printf("Starting up the probe at interface %v", iface.Attrs().Name)

	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker

	// Create a ring buffer reader
	pipe := probe.bpfObjects.probeMaps.Pipe
	ringreader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Println("Failed creating ringbuf reader")
		return err
	}

	go func() {
		for {
			event, err := ringreader.Read()
			if err != nil {
				log.Printf("Failed reading ringbuf event: %v", err)
				return
			}
			flowrecord, ok := UnmarshalFlowRecord(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall flow record: %+v", event.RawSample)
				continue
			}
			// if flow record fin, delete from flow table
			if flowrecord.fm.FlowClosed == 1 || flowrecord.fm.FlowClosed == 2 {
				writeFlowStatsToFile("flow_tcp_complete_stats.txt", flowrecord.fm)
			}
		}
	}()

	for {

		<-ctx.Done()

		EvictMapEntries(flowstrackermap, ft)
		return probe.Close(ft)

	}
}
