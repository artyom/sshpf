// Command sshpf provides a minimalistic ssh server only allowing port
// forwarding to an (optionally) limited set of addresses.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/ssh"
)

func main() {
	args := runArgs{
		AuthKeysFile: "authorized_keys",
		HostKeyFile:  "id_rsa",
		Addr:         "localhost:2022",
		Timeout:      3 * time.Minute,
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		log.Fatal(err)
	}
}

type runArgs struct {
	AuthKeysFile string        `flag:"auth,path to authorized_keys file"`
	HostKeyFile  string        `flag:"hostKey,path to private host key file"`
	Addr         string        `flag:"addr,address to listen"`
	Destinations string        `flag:"allowed,file with list of allowed to connect host:port pairs"`
	Timeout      time.Duration `flag:"timeout,IO timeout on client connections"`
}

func run(args runArgs) error {
	auth, err := authChecker(args.AuthKeysFile)
	if err != nil {
		return err
	}
	hostKey, err := loadHostKey(args.HostKeyFile)
	if err != nil {
		return err
	}
	var destinations []string
	if args.Destinations != "" {
		ss, err := loadDestinations(args.Destinations)
		if err != nil {
			return err
		}
		destinations = ss
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: auth,
		ServerVersion:     "SSH-2.0-generic",
	}
	config.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", args.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		tc := conn.(*net.TCPConn)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(3 * time.Minute)
		if args.Timeout > 0 {
			conn = timeoutConn{tc, args.Timeout}
		}
		go handleConn(conn, config, destinations...)
	}
}

// timeoutConn extends deadline after successful read or write operations
type timeoutConn struct {
	*net.TCPConn
	d time.Duration
}

func (c timeoutConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func handleConn(nConn net.Conn, config *ssh.ServerConfig, allowedDestinations ...string) error {
	defer nConn.Close()
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		case "session":
			go handleSession(newChannel)
		case "direct-tcpip":
			go handleDial(newChannel, allowedDestinations...)
		}
	}
	return nil
}

func handleDial(newChannel ssh.NewChannel, allowedDestinations ...string) error {
	host, port, err := decodeHostPortPayload(newChannel.ExtraData())
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "bad payload")
		return err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if len(allowedDestinations) > 0 {
		for _, dest := range allowedDestinations {
			if addr == dest {
				goto dial
			}
		}
		return newChannel.Reject(ssh.Prohibited, "connection to this address is prohibited")
	}
dial:
	rconn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return newChannel.Reject(ssh.ConnectionFailed, "connection failed")
	}
	defer rconn.Close()
	rconn.(*net.TCPConn).SetKeepAlive(true)
	rconn.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	go io.Copy(channel, rconn)
	_, err = io.Copy(rconn, channel)
	return err
}

func handleSession(newChannel ssh.NewChannel) error {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer channel.Close()
	go func(reqs <-chan *ssh.Request) {
		for req := range reqs {
			req.Reply(req.Type == "shell", nil)
		}
	}(requests)
	_, err = io.Copy(ioutil.Discard, channel)
	if err == nil || err == io.EOF {
		// this makes ssh client exit with 0 status on client-initiated
		// disconnect (eg. ^D)
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	}
	return err
}

func loadHostKey(name string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func authChecker(name string) (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkeys [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(sc.Bytes())
		if err != nil {
			return nil, err
		}
		pkeys = append(pkeys, pk.Marshal())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyBytes := key.Marshal()
		for _, k := range pkeys {
			if bytes.Equal(keyBytes, k) {
				return nil, nil
			}
		}
		return nil, errors.New("no keys matched")
	}, nil
}

func decodeHostPortPayload(b []byte) (host string, port int, err error) {
	// https://tools.ietf.org/html/rfc4254#section-7.2
	msg := struct {
		Host string
		Port uint32
		Data []byte `ssh:"rest"`
	}{}
	return msg.Host, int(msg.Port), ssh.Unmarshal(b, &msg)
}

func loadDestinations(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var out []string
	for scanner.Scan() {
		if b := scanner.Bytes(); len(b) == 0 || b[0] == '#' {
			continue
		}
		out = append(out, scanner.Text())
	}
	return out, scanner.Err()
}
