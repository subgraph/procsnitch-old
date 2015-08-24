package procsnitch

import (
	"fmt"
	"path/filepath"
	"os"
	"strings"
	"syscall"
	"io/ioutil"
	"bufio"
	"strconv"
	"encoding/hex"
	"net"
)

type Protocol int

const (
	TCP		Protocol = iota
	UDP
)

func (p Protocol) String() (result string) {
	switch p {
	case TCP:
		result = "tcp"
	case UDP:
		result = "udp"
	}
	return
}

type Addr struct {
	IP net.IP
	Port int
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

type SocketStatus struct {
	Id 			int
	LocalAddr 	Addr
	RemoteAddr	Addr
	Status		ConnectionStatus
	TxQueue		int
	RxQueue		int
	Tr			int
	TmWhen		int
	Retrnsmt	int
	Uid			int
	Timeout		int
	Inode		uint64
}

type ConnectionStatus int

const (
	ESTABLISHED 	ConnectionStatus = iota
	SYN_SENT
	SYN_RECV
	FIN_WAIT1
	FIN_WAIT2
	TIME_WAIT
	CLOSE
	CLOSE_WAIT
	LAST_ACK
	LISTEN
	CLOSING
)

func (c ConnectionStatus) String() (string) {
	switch c {
	case ESTABLISHED:
		return "ESTABLISHED"
	case SYN_SENT:
		return "SYN_SENT"
	case SYN_RECV:
		return "SYN_RECV"
	case FIN_WAIT1:
		return "FIN_WAIT1"
	case	FIN_WAIT2:
		return  "FIN_WAIT2"
	case TIME_WAIT:
		return "TIME_WAIT"
	case CLOSE:
		return "CLOSE"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case LAST_ACK:
		return "LAST_ACK"
	case LISTEN:
		return "LISTEN"
	case CLOSING:
		return "CLOSING"
	default:
		return "Invalid Connection Status"
	}
}

type UidGid struct {
	realId, effectiveId, savedId, fileSystemId int
}

func ParseIp(ip string) (net.IP, error) {
	var result net.IP
	dst, err := hex.DecodeString(ip)
	if err != nil {
		return result, fmt.Errorf("Error parsing IP: %s", err)
	}
	// Reverse byte order -- /proc/net/tcp etc. is little-endian
	// TODO: Does this vary by architecture?
	for i, j := 0, len(dst)-1; i < j; i, j = i+1, j-1 {
		dst[i], dst[j] = dst[j], dst[i]
	}
	result = net.IP(dst)
	return result, nil
}

func ParsePort(port string) (int, error) {
	var result int
	p64, err := strconv.ParseInt(port, 16, 32)
	if err != nil {
		return result, fmt.Errorf("Error parsing port: %s", err)
	}
	result = int(p64)
	return result, nil
}

func GetOpenFileDescriptors() ([]string, error) {
	var results []string
	paths, err := filepath.Glob("/proc/[0-9]*/fd/*")
	if err != nil {
		return results, fmt.Errorf("Error globbing /proc: %s", err)
	}
	results = make([]string, 0)
	for _, path := range paths {
		results = append(results, path)
	}
	return results, nil
}

func FindSocketsByDestination(host string, port string, proto Protocol) ([]SocketStatus, error) {
	var destAddr Addr
	var results []SocketStatus
	if port != "" {
		portInt, err := strconv.Atoi(port)
		if err != nil {
			return results, fmt.Errorf("Error parsing port: %s", err)
		}
		destAddr = Addr{net.ParseIP(host), portInt}
	}
	destAddr = Addr{net.ParseIP(host), 0}
	socketList, err := GetSocketList(proto)
	if err != nil {
		return results, err
	}
	for _, socket := range socketList {
		socketStatus, err := ParseSocketStatus(socket)
		if err != nil {
			return results, err
		}
		if port != "" {
			if socketStatus.RemoteAddr.String() == destAddr.String() {
				results = append(results, socketStatus)
			}
		} else {
			if socketStatus.RemoteAddr.IP.String() == destAddr.IP.String() {
				results = append(results, socketStatus)
			}
		}
	}
	return results, nil
}


func FindExecutablePathByInode(inode uint64) (string, error) {
	var executablePath string
	search := fmt.Sprintf("socket:[%d]", inode)
	paths, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, path := range paths {
		_, err := os.Stat(path)
		if err == nil {
			link, err := os.Readlink(path)
			if err != nil {
				err := fmt.Errorf("Error %s in os.Readlink: %v", err, link)
				return executablePath, err
			}
			if link == search {
				pid := strings.Split(path, "/")[2]
				executablePath, err = GetExecutablePathFromPid(pid)
			}
		}
	}
	return executablePath, nil
}

func GetExecutablePathFromPid(pid string) (string, error) {
	var result string
	exePath := fmt.Sprintf("/proc/%s/exe", pid)
	result, err := os.Readlink(exePath)
	if err != nil {
		return result, err
	}
	return result, nil
}

func GetInodeFromPath(path string) (uint64, error) {
	var result uint64
	// TODO: Double stat-ing not efficient, re-implement
	fInfo, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	fstat := fInfo.Sys().(*syscall.Stat_t)
	result = fstat.Ino
	return result, nil
}


func GetSocketList(proto Protocol) ([]string, error) {
	var results []string
	path := fmt.Sprintf("/proc/net/%s", proto)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return results, err
	}
	lines := strings.Split(string(data), "\n")
	results = lines[1:len(lines) - 1]
	return results, nil
}

func ParseSocketStatus(line string) (SocketStatus, error) {
	var result SocketStatus
	id, err := strconv.Atoi(strings.TrimSuffix(strings.Fields(line)[0], ":"))
	if err != nil {
		return result, fmt.Errorf("Error parsing socket id: %s", err)
	}
	localIpPort := strings.Split(strings.Fields(line)[1], ":")
	localIp, err := ParseIp(localIpPort[0])
	if err != nil {
		return result, err
	}
	localPort, err := ParsePort(localIpPort[1])
	if err != nil {
		return result, err
	}
	localAddr := Addr{localIp, localPort}
	remoteIpPort := strings.Split(strings.Fields(line)[2], ":")
	remoteIp, err := ParseIp(remoteIpPort[0])
	if err != nil {
		return result, err
	}
	remotePort, err := ParsePort(remoteIpPort[1])
	if err != nil {
		return result, err
	}
	remoteAddr := Addr{remoteIp, remotePort}
	st64, err := strconv.ParseInt(
		fmt.Sprintf("0x%s",strings.Fields(line)[3]), 0, 32)
	if err != nil {
		return result, fmt.Errorf("Error parsing ConnectionStatus: %s", err)
	}
	status := ConnectionStatus(st64)
	txRxQueue := strings.Split(strings.Fields(line)[4], ":")
	txQueue, err := strconv.Atoi(txRxQueue[0])
	if err != nil {
		return result, fmt.Errorf("Error parsing txQueue: %s", err)
	}
	rxQueue, err := strconv.Atoi(txRxQueue[1])
	if err != nil {
		return result, fmt.Errorf("Error parsing rxQueue: %s", err)
	}
	trTmWhen := strings.Split(strings.Fields(line)[5], ":")
	tr, err := strconv.Atoi(trTmWhen[0])
	if err != nil {
		return result, fmt.Errorf("Error parsing tr: %s", err)
	}
	tmw64, err := strconv.ParseInt(
		fmt.Sprintf("0x%s", trTmWhen[1]), 0, 32)
	if err != nil {
		return result, fmt.Errorf("Error parsing tmWhen: %s", err)
	}
	tmWhen := int(tmw64)
	retrnsmt, err := strconv.Atoi(strings.Fields(line)[6])
	if err != nil {
		return result, fmt.Errorf("Error parsing retrnsmt: %s", err)
	}
	uid, err := strconv.Atoi(strings.Fields(line)[7])
	if err != nil {
		return result, fmt.Errorf("Error parsing uid: %s", err)
	}
	timeout, err := strconv.Atoi(strings.Fields(line)[8])
	if err != nil {
		return result, fmt.Errorf("Error parsing timeout: %s", err)
	}
	inode, err := strconv.ParseUint(strings.Fields(line)[9], 10, 64)
	if err != nil {
		return result, fmt.Errorf("Error parsing indoe: %s")
	}
	result = SocketStatus{id,
		localAddr,
		remoteAddr,
		status,
		txQueue,
		rxQueue,
		tr,
		tmWhen,
		retrnsmt,
		uid,
		timeout,
		inode}
	return result, nil
}

func GetUidFromPid(pid string) (UidGid, error) {
	var uidGid UidGid
	path := fmt.Sprintf("/proc/%s/status", pid)
	file, err := os.Open(path)
	if err != nil {
		return uidGid, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Uid:") {
			fields := strings.Fields(scanner.Text())[1:]
			var ints [4]int
			for  i := 0; i < len(fields); i++ {
				fmt.Println(i)
				j, _ := strconv.Atoi(fields[i])
				ints[i] = j
			}
			uidGid = UidGid{ints[0],
				ints[1],
				ints[2],
				ints[3]}
		}
	}
	if err = scanner.Err(); err != nil {
		return uidGid, err
	}
	return uidGid, nil
}

func GetExePathByFd() ([]string, error) {
	var results []string
	fds, err := GetOpenFileDescriptors()
	if err != nil {
		return results, err
	}
	for _, fdPath := range fds {
			pid := strings.Split(fdPath, "/")[2]
			exe, err := GetExecutablePathFromPid(pid)
			if err != nil {
				return results, err
			}
			results = append(results, exe)
	}
	return results, nil
}

func GetInodesFromPaths(paths []string) (map[string]uint64, error) {
	var pathInode map[string]uint64
	for _, path := range paths {
		inode, err := GetInodeFromPath(path)
		if err != nil {
			return pathInode, err
		}
		pathInode[path] = inode
	}
	return pathInode, nil
}


