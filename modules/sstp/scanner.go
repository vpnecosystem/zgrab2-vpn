// Package sstp contains the module implementation for SSTP HTTP(S) connection establishment
//
// The module performs a complete TLS handshake to then send an HTTP SSTP_DUPLEX_POST request. The default port is 443.
package sstp

import (
	"crypto/tls"
	"io"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type TLSFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	File string `long:"file" default:"" description:"file to write responses to" `
}

type TLSScanner struct {
	config *TLSFlags
}

type TLSModule struct {
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Status         string `json:"status,omitempty"`
	Content_Length string `json:"content_length,omitempty"`
	Host           string `json:"host,omitempty"`
	Content_Type   string `json:"content_type,omitempty"`
	Server         string `json:"server,omitempty"`
	Misc           string `json:"misc,omitempty"`
	Body           string `json:"body,omitempty"`
}

// NewFlags returns an empty Flags object.
func (module *TLSModule) NewFlags() interface{} {
	return new(TLSFlags)
}

// NewScanner returns a new instance Scanner instance.
func (module *TLSModule) NewScanner() zgrab2.Scanner {
	return new(TLSScanner)
}

// Help returns module-specific help
func (flags *TLSFlags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *TLSScanner) Protocol() string {
	return "sstp"
}

// GetName returns the name defined in the Flags.
func (scanner *TLSScanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *TLSScanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Description returns an overview of this module.
func (module *TLSModule) Description() string {
	return "Send an SSTP_DUPLEX_POST request and check if server accepts the response"
}

// InitPerSender does nothing in this module.
func (scanner *TLSScanner) InitPerSender(senderID int) error {
	return nil
}

func (f *TLSFlags) Validate(args []string) error {
	return nil
}

// Init initializes the Scanner with the command-line flags.
func (scanner *TLSScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*TLSFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	scanner.config = f
	return nil
}

func getProbe(host string) []byte {
	first_part := "\x53\x53\x54\x50\x5f\x44\x55\x50\x4c\x45\x58\x5f\x50\x4f\x53\x54\x20\x2f\x73\x72\x61\x5f\x7b\x42\x41\x31\x39\x35\x39\x38\x30\x2d\x43\x44\x34\x39\x2d\x34\x35\x38\x62\x2d\x39\x45\x32\x33\x2d\x43\x38\x34\x45\x45\x30\x41\x44\x43\x44\x37\x35\x7d\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x53\x53\x54\x50\x43\x4f\x52\x52\x45\x4c\x41\x54\x49\x4f\x4e\x49\x44\x3a\x20\x7b\x31\x39\x37\x33\x30\x44\x36\x30\x2d\x39\x30\x41\x30\x2d\x34\x36\x32\x33\x2d\x38\x43\x34\x34\x2d\x36\x38\x38\x44\x37\x36\x32\x41\x41\x41\x31\x36\x7d\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x31\x38\x34\x34\x36\x37\x34\x34\x30\x37\x33\x37\x30\x39\x35\x35\x31\x36\x31\x35\x0d\x0a\x48\x6f\x73\x74\x3a\x20"
	end_part := "\x0d\x0a\x0d\x0a"
	complete_string := first_part + host + end_part
	return []byte(complete_string)
}

// return tls config that skips hostname verification
// this can be extended to, e.g., log SSL keys
func tlsConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
	}
	return &tlsConfig, nil
}

// Scan opens a TCP connection to the target (default port 443), then performs
// a TLS handshake. If the handshake gets past the ServerHello stage, an SSTP_DUPLEX_POST
// HTTP request is sent out and the response is logged
func (s *TLSScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	cfg, _ := tlsConfig()

	var host string

	//check if IP or domain name is passed and add it to the address to connect to
	if t.IP != nil {
		host = t.IP.String()
	} else {
		host = t.Host()
		cfg.ServerName = host
	}

	//establish TCP connection
	tcp_conn, err := t.Open(&s.config.BaseFlags)

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer tcp_conn.Close()

	//establish TLS connection on top of tcp net.Conn object
	conn := tls.Client(tcp_conn, cfg)

	if conn != nil {
		defer conn.Close()
	}

	conn.SetDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))

	err = conn.Handshake()

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	//send probe and read response
	probe := getProbe(host)
	var (
		readerr error
		ret     []byte
	)

	_, err = conn.Write(probe)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	ret, readerr = zgrab2.ReadAvailable(conn)
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	//parse response
	var results Results

	splits := strings.Split(string(ret), "\r\n") //split by new lines

	var status string
	var c_length string
	var c_type string
	var server string
	var misc string
	var body string

	//parse for specific header fields
	for i, elem := range splits {
		if i == 0 { //first element is the status message
			status = elem
		} else if strings.Contains(elem, "Content-Length:") { //parse content length
			c_length = elem
		} else if strings.Contains(elem, "Content-Type:") { //parse content type
			c_type = elem
		} else if strings.Contains(elem, "Date:") { //skip date since zgrab logs the time anyway
		} else if strings.Contains(elem, "Host:") { //skip host
		} else if strings.Contains(elem, "Server:") { //parse server
			server = elem
		} else if i == len(splits)-1 { //last element should be message body or empty
			if elem != "" {
				if status == "HTTP/1.1 200 OK" {
					body = elem
				}
			}
		} else if elem != "" { //nothing matches, append to misc string and add line breaks again
			if status == "HTTP/1.1 200 OK" {
				misc = misc + elem + "\r\n"
			}
		}
	}
	results = Results{Status: status, Content_Length: c_length, Server: server, Content_Type: c_type, Host: host, Misc: misc, Body: body}

	return zgrab2.SCAN_SUCCESS, &results, nil
}

// RegisterModule is called by modules/sstp.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module TLSModule

	_, err := zgrab2.AddCommand("sstp", "SSTP request", module.Description(), 443, &module)
	if err != nil {
		log.Fatal(err)
	}
}
