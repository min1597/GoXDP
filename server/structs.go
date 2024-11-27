package main

import (
	"github.com/cilium/ebpf/link"
	"log"
	"net/netip"
	"time"
)

type BpfIpv4LpmKey struct {
	Prefixlen uint32
	Target    uint32
}

// the Application struct holds the shared data or the data that needs to be used frequently.
type Application struct {
	InfoLog          *log.Logger
	ErrorLog         *log.Logger
	BpfObjects       *bpfObjects
	Interfaces       *[]string
	LoadedInterfaces map[string]link.Link
	TimeoutList      map[BpfIpv4LpmKey]time.Time
	// Is_loaded        bool
}

// Structs used by xdpLoad and xdpUnload handlers
type load struct {
	Mode       *string `json:"mode"`
	Interfaces *string `json:"interfaces"`
	Target     *string `json:"target"`
	Action     *string `json:"action"`
	Timeout    *uint   `json:"timeout"`
}

// Structs for XDP status
type statusMapJson struct {
	Target          netip.Addr `json:"target"`
	Src_packets      uint64     `json:"src_count"`
	Src_size_packets uint64     `json:"src_bytes_dropped"`
	Dst_packets      uint64     `json:"dst_count"`
	Dst_size_packets uint64     `json:"dst_bytes_dropped"`
}
type statusTimeoutOutput struct {
	Target    string `json:"target"`
	Timeout   string `json:"timeout"`
	Remaining int    `json:"remaining_time"`
}
type statusMapOutput struct {
	Interfaces []string              `json:"interfaces"`
	Blocked    []string              `json:"blocked"`
	Timeout    []statusTimeoutOutput `json:"timeout"`
	Status     []statusMapJson       `json:"stats"`
}
