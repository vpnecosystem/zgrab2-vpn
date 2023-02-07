// Package tcp contains the module implementation for TCP
//
// The module performs a complete TCP handshake to then send TCP packages. The default port is 443
package tcp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags

	Protocol  string `long:"protocol" default:"\\n" description:"Send an initiation request of the VPN protocol specified here. This can be either 'pptp' or 'openvpn'" `
	ProbeFile string `long:"probe-file" description:"Read probe from file as hex stream and convert to byte array. Mutually exclusive with --protocol."`
	MaxTries  int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
	Hex       bool   `long:"hex" description:"Store banner value in hex. "`
	File      string `long:"file" default:"" description:"file to write responses to" `
	HMAC      bool   `long:"hmac" description:"Specify if HMAC should be used in OpenVPN request"`
	KeyMethod int    `long:"keymethod" default:"2" description:"Specify which KeyMethod to use for OpenVPN"`
	SessionID string `long:"session-id" default:"1a2b3c4d1a2b3c4d" description:"Session ID to use for OpenVPN request"`
}

// Module is an implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	probe  []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Response string `json:"response,omitempty"`
}

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Send a TCP probe and read the response"
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	if flags.Protocol != "\\n" && flags.ProbeFile != "" {
		log.Fatal("Cannot set both --protocol and --probe-file")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "tcp"
}

// GetName returns the name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// InitPerSender does nothing in this module.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	var err error
	var bytes []byte
	f, _ := flags.(*Flags)
	scanner.config = f
	if len(f.ProbeFile) != 0 {
		bytes, err = ioutil.ReadFile(f.ProbeFile)
		if err != nil {
			log.Fatal("Failed to open probe file")
			return zgrab2.ErrInvalidArguments
		}
		string_probe := string(bytes)
		scanner.probe, _ = hex.DecodeString(string_probe)
	} else {
		if len(scanner.probe) == 0 {
			strProtocol, err := strconv.Unquote(fmt.Sprintf(`"%s"`, scanner.config.Protocol))
			strProbe := ""
			opcode := ""
			if err != nil {
				panic("Probe error")
			}
			//determine which probe to use
			if strProtocol == "pptp" {
				strProbe = "\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				scanner.probe = []byte(strProbe)
			}
			if strProtocol == "openvpn" {
				length := ""

				//get session ID
				session := scanner.config.SessionID

				//generate opcode
				if scanner.config.KeyMethod == 1 {
					opcode = "08"
				} else if scanner.config.KeyMethod == 2 {
					opcode = "38"
				}

				//check if hmac should be included
				if !scanner.config.HMAC {
					length = "000e"
					strProbe = length + opcode + session + "0000000000"
				} else if f.HMAC { //hmac generation
					length = "002a"
					hmac := hmac.New(sha1.New, []byte("secret"))
					hmac.Write([]byte(length + opcode + session))
					hash := hex.EncodeToString((hmac.Sum(nil)))

					//get timestamp
					timestamp := strconv.FormatInt(time.Now().Unix(), 16)

					packet_id := "00000001"

					//put everything together
					strProbe = length + opcode + session + hash + packet_id + timestamp + "0000000000"
				}
				scanner.probe, _ = hex.DecodeString(strProbe)
			}
		}
	}
	return nil
}

// Scan opens a TCP connection to the target (default port 443), then performs
// a TLS handshake. If the handshake gets past the ServerHello stage, the
// handshake log is returned (along with any other TLS-related logs, such as
// heartbleed, if enabled).
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		err     error
		readerr error
	)

	//try to open connection for specified amount of tries
	for try := 0; try < scanner.config.MaxTries; try++ {
		try++
		conn, err = target.Open(&scanner.config.BaseFlags)
		if err != nil {
			continue
		}

		break
	}

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	defer conn.Close()

	//send probe to open connection and check for response
	var ret []byte
	for try := 0; try < scanner.config.MaxTries; try++ {
		try++
		_, err = conn.Write(scanner.probe)
		ret, readerr = zgrab2.ReadAvailable(conn)
		if err != nil {
			continue
		}
		if readerr != io.EOF && readerr != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), nil, readerr
	}

	var results Results
	if scanner.config.Hex {
		results = Results{Response: hex.EncodeToString(ret)}
	} else {
		results = Results{Response: string(ret)}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}

// RegisterModule is called by modules/tcp.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module

	_, err := zgrab2.AddCommand("tcp", "TCP probe", module.Description(), 443, &module)
	if err != nil {
		log.Fatal(err)
	}
}
