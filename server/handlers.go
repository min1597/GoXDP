package main

import (
	"encoding/json"
	"fmt"
	"github.com/ahsifer/goxdp/helpers"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Load XDP program into the provided interfaces
func (app *Application) xdpLoad(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	//Request body parsing
	var body load
	err := json.NewDecoder(request.Body).Decode(&body)
	if err != nil {
		app.ErrorLog.Printf("Cannot parse json request -> %v\n", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	//check for empty inputs
	if body.Interfaces == nil || body.Mode == nil {
		errMessage := "Request body does not include mode or Interfaces names to load"
		app.ErrorLog.Printf(errMessage)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
		return
	}
	//parse input interfaces
	stringSlice := strings.Split(*body.Interfaces, ",")
	app.Interfaces = &stringSlice

	//Create Modes Array
	modes := make(map[string]link.XDPAttachFlags)
	modes["hw"] = link.XDPOffloadMode
	modes["skb"] = link.XDPGenericMode
	modes["nv"] = link.XDPDriverMode
	loadMode, ok := modes[*body.Mode]
	if !ok {
		app.ErrorLog.Printf("Invalid Mode")
		helpers.Error(response, "Invalid Mode", http.StatusBadRequest)
		return
	}

	//default interface details
	interLink := link.XDPOptions{
		Program: app.BpfObjects.Firewall,
		Flags:   loadMode,
	}
	for _, value := range *app.Interfaces {
		//check if XDP code is already loaded
		_, ok := app.LoadedInterfaces[value]
		if ok {
			errMsg := "XDP is already loaded to the interface: " + value
			app.InfoLog.Print(errMsg)
			continue
		}
		iface, err := net.InterfaceByName(value)
		if err != nil {
			errMessage := "interface does not exists " + value + " -> " + err.Error()
			app.ErrorLog.Printf(errMessage)
			helpers.Error(response, errMessage, http.StatusBadRequest)
			return
		}
		interLink.Interface = iface.Index
		l, err := link.AttachXDP(interLink)
		if err != nil {
			errorMSG := "Cannot attach XDP to " + value + " XDP might be already loaded to the interface  -> " + err.Error()
			app.ErrorLog.Printf(errorMSG)
			helpers.Error(response, errorMSG, http.StatusBadRequest)
			return
		}
		app.LoadedInterfaces[value] = l
	}
	response.WriteHeader(200)
	return
}

// unload XDP programs
func (app *Application) xdpUnload(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	if len(app.LoadedInterfaces) == 0 {
		app.ErrorLog.Printf("XDP program is not loaded")
		helpers.Error(response, "XDP program is not loaded to any of the interfaces", http.StatusBadRequest)
		return
	}
	//Request body parsing
	var body load
	err := json.NewDecoder(request.Body).Decode(&body)
	if err != nil {
		app.ErrorLog.Printf("Cannot parse json request -> %v\n", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	//check for empty inputs
	if body.Interfaces == nil {
		app.ErrorLog.Printf("Request body does not include Interfaces names to unload")
		helpers.Error(response, "Request body does not include Interfaces names to unload", http.StatusBadRequest)
		return
	}

	//parse input interfaces
	stringSlice := strings.Split(*body.Interfaces, ",")
	if stringSlice[0] == "all" {
		if len(app.LoadedInterfaces) == 0 {
			helpers.Error(response, "No XDP program loaded", http.StatusBadRequest)
			return
		}
		for key, value := range app.LoadedInterfaces {
			err = value.Close()
			if err != nil {
				app.ErrorLog.Printf("Cannot remove XDP from the interface -> %v\n", err)
				helpers.Error(response, "Cannot remove XDP from the interface", http.StatusBadRequest)
				return
			}
			//delete the xdp program from the map
			delete(app.LoadedInterfaces, key)
		}
	} else {
		for _, value := range stringSlice {
			val, ok := app.LoadedInterfaces[value]
			if !ok {
				response.Write([]byte("no XDP code loaded to the interface: " + value))
				continue
			}
			err = val.Close()
			if err != nil {
				app.ErrorLog.Printf("Cannot remove XDP from the interface -> %v\n", err)
				helpers.Error(response, "Cannot remove XDP from the interface: "+value, http.StatusBadRequest)
				return
			}
			delete(app.LoadedInterfaces, value)
		}
	}
	response.WriteHeader(200)
	return
}

// status XDP programs
func (app *Application) xdpBlock(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	//Request body parsing
	var body load
	err := json.NewDecoder(request.Body).Decode(&body)
	if err != nil {
		app.ErrorLog.Printf("Cannot parse json request -> %v\n", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	// check for empty inputs
	if body.Target == nil || body.Action == nil || body.Timeout == nil {
		app.ErrorLog.Printf("Request body does not include target, action, or timeout")
		helpers.Error(response, "Request body does not include target, action, or timeout", http.StatusBadRequest)
		return
	}

	//Check if input IP is valid
	validIP, err := helpers.IpChecker(*body.Target)
	if err != nil {
		app.ErrorLog.Printf("Invalid IP address or subnet -> %s", err)
		helpers.Error(response, "Invalid Request Body", http.StatusBadRequest)
	}
	stringSlice := strings.Split(*validIP, "/")
	prefix, err := strconv.ParseUint(stringSlice[1], 10, 32)
	if err != nil {
		errMsg := "Input prefix cannot be parsed to unit32 -> " + err.Error()
		app.ErrorLog.Print(errMsg)
		helpers.Error(response, errMsg, http.StatusBadRequest)
		return
	}
	//Convert the IP address to decimal with big endian format
	decimalIP, err := helpers.IP4toInt(stringSlice[0])
	if err != nil {
		app.ErrorLog.Printf("Cannot convert input IP address to big endian decimal format -> %s", err)
		helpers.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	key := BpfIpv4LpmKey{
		Prefixlen: uint32(prefix),
		Target:    *decimalIP,
	}

	if *body.Action == "block" {
		err = app.BpfObjects.BlockedIpv4.Update(&key, uint8(1), ebpf.UpdateAny)
		if err != nil {
			app.InfoLog.Print(err)
			helpers.Error(response, "Unable to update blocked_ipv4 LPM map", http.StatusInternalServerError)
			return
		}

		// Check if the key exists in the timeout map or not
		// _, ok := app.TimeoutList[key]

		if *body.Timeout != 0 {
			app.TimeoutList[key] = time.Now().Add(time.Duration(*body.Timeout) * time.Second)
		}

	} else if *body.Action == "allow" {
		err = app.BpfObjects.BlockedIpv4.Delete(&key)
		if err != nil {
			app.InfoLog.Print(err.Error())
			helpers.Error(response, "IP address or subnet already not blocked", http.StatusInternalServerError)
			return
		}
		delete(app.TimeoutList, key)

	} else {
		helpers.Error(response, "Bad input action", http.StatusBadRequest)
	}
	response.WriteHeader(200)
	return
}

func (app *Application) xdpStatus(response http.ResponseWriter, request *http.Request) {
	var output statusMapOutput

	//prepare status for the blocked IP addresses
	statusMapOutput := []statusMapJson{}
	iter := app.BpfObjects.Status.Iterate()
	//the key to single status map is ip address
	var key netip.Addr
	//Since the status map is LRU per cpu hash map then the returned value for each key is array size equal to the cpu cores
	val := make([]bpfStatusMapVal, runtime.NumCPU())
	for iter.Next(&key, &val) {
		var src_packets uint64 = 0
		var src_size_packets uint64 = 0
		var dst_packets uint64 = 0
		var dst_size_packets uint64 = 0
		for _, value := range val {
			src_packets += value.SrcPackets
			src_size_packets += value.SrcSizePackets
			dst_packets += value.DstPackets
			dst_size_packets += value.DstSizePackets
		}
		statusMapOutput = append(statusMapOutput, statusMapJson{
			Target:          key,
			Src_packets:      src_packets,
			Src_size_packets: src_size_packets,
			Dst_packets:      dst_packets,
			Dst_size_packets: dst_size_packets,
		})
	}
	if err := iter.Err(); err != nil {
		app.InfoLog.Print(err)
	}

	//prepare the blocked IP addresses from the LPM map
	blockedMapOutput := []string{}
	var blockedMapKey uint64
	var blockedMapVal uint8
	iter = app.BpfObjects.BlockedIpv4.Iterate()
	for iter.Next(&blockedMapKey, &blockedMapVal) {
		ip := (uint32)((blockedMapKey & 0xFFFFFFFF00000000) >> 32)
		prefix := (uint32)(blockedMapKey & 0xFFFFFFFF)
		blockedMapOutput = append(blockedMapOutput, fmt.Sprintf("%s/%d", helpers.IntToIPv4(ip), prefix))

	}
	if err := iter.Err(); err != nil {
		app.InfoLog.Print(err)
	}

	//Prepare the name of the interfaces that the XDP program is loaded to
	loadedInterfaces := []string{}
	for key := range app.LoadedInterfaces {
		loadedInterfaces = append(loadedInterfaces, key)
	}

	//prepare the timeouts of the blocked subnets
	timeoutOutput := []statusTimeoutOutput{}
	for targetKey, timeValue := range app.TimeoutList {
		timeoutOutput = append(timeoutOutput, statusTimeoutOutput{
			Target:    helpers.IntToIPv4(targetKey.Target) + "/" + strconv.FormatUint(uint64(targetKey.Prefixlen), 10),
			Timeout:   timeValue.Format("2006-01-02 15:04:05"),
			Remaining: int(timeValue.Sub(time.Now()).Seconds()),
		})
	}

	//prepare our output
	output.Blocked = blockedMapOutput
	output.Status = statusMapOutput
	output.Interfaces = loadedInterfaces
	output.Timeout = timeoutOutput

	finalResponse, err := json.Marshal(output)
	if err != nil {
		app.ErrorLog.Println("Unable to parse json data", err)
		helpers.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Write(finalResponse)
	return
}

// status XDP programs
func (app *Application) xdpBlockedFlush(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")

	//the array that will store the blocked IP addresses and subnets
	var blockedMap []BpfIpv4LpmKey
	//prepare the blocked IP addresses from the LPM map
	var blockedMapKey uint64
	var blockedMapVal uint8
	iter := app.BpfObjects.BlockedIpv4.Iterate()
	for iter.Next(&blockedMapKey, &blockedMapVal) {
		ip := (uint32)((blockedMapKey & 0xFFFFFFFF00000000) >> 32)
		prefix := (uint32)(blockedMapKey & 0xFFFFFFFF)
		//append the returned subnet to the blockedMap
		key := BpfIpv4LpmKey{
			Prefixlen: prefix,
			Target:    ip,
		}
		blockedMap = append(blockedMap, key)
	}
	if err := iter.Err(); err != nil {
		app.InfoLog.Print(err)
	}

	//loop on the blocked map and unblock the subnets
	for _, value := range blockedMap {
		err := app.BpfObjects.BlockedIpv4.Delete(&value)
		if err != nil {
			app.InfoLog.Print(err.Error())
			helpers.Error(response, "IP address or subnet already not blocked", http.StatusInternalServerError)
			return
		}
		delete(app.TimeoutList, value)
	}

	response.WriteHeader(200)
	return
}

// status XDP programs
func (app *Application) xdpStatusFlush(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")

	//prepare status array for the IP addresses in the status map
	statusMapOutput := []netip.Addr{}
	iter := app.BpfObjects.Status.Iterate()
	//the key of the status map is single IP address
	var key netip.Addr
	//Since the status map is LRU per cpu hash map then the returned value for each key is array size equal to the cpu cores
	val := make([]bpfStatusMapVal, runtime.NumCPU())
	for iter.Next(&key, &val) {
		var src_packets uint64 = 0
		var src_size_packets uint64 = 0
		var dst_packets uint64 = 0
		var dst_size_packets uint64 = 0
		for _, value := range val {
			src_packets += value.SrcPackets
			src_size_packets += value.SrcSizePackets
			dst_packets += value.DstPackets
			dst_size_packets += value.DstSizePackets
		}
		statusMapOutput = append(statusMapOutput, key)
	}
	if err := iter.Err(); err != nil {
		app.InfoLog.Print(err)
	}

	//loop on the status map and remove them from the map the subnets
	for _, value := range statusMapOutput {
		err := app.BpfObjects.Status.Delete(&value)
		if err != nil {
			app.InfoLog.Print(err.Error())
			helpers.Error(response, "IP address or subnet already not blocked", http.StatusInternalServerError)
			return
		}
	}

	response.WriteHeader(200)
	return
}
