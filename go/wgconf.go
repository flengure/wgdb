package main

import (
	"fmt"
	"strconv"
	"strings"
)

// wgConfInterface holds the parsed [Interface] section of a wg0.conf.
type wgConfInterface struct {
	Name       string
	PrivateKey string
	AddressV4  string
	AddressV6  string
	ListenPort int
	DNS        string
	MTU        int
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
}

// wgConfPeer holds a parsed [Peer] section.
type wgConfPeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          string
	Endpoint            string
	PersistentKeepalive int
}

// wgConf is the full parsed config.
type wgConf struct {
	wgConfInterface
	Peers []wgConfPeer
}

// parseWGConf parses a wg0.conf INI-format string.
func parseWGConf(text string) (*wgConf, error) {
	conf := &wgConf{}
	var currentPeer *wgConfPeer
	inInterface := false

	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.EqualFold(line, "[Interface]") {
			inInterface = true
			currentPeer = nil
			continue
		}
		if strings.EqualFold(line, "[Peer]") {
			if currentPeer != nil {
				conf.Peers = append(conf.Peers, *currentPeer)
			}
			currentPeer = &wgConfPeer{}
			inInterface = false
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if inInterface {
			switch strings.ToLower(key) {
			case "privatekey":
				conf.PrivateKey = val
			case "address":
				for _, addr := range strings.Split(val, ",") {
					addr = strings.TrimSpace(addr)
					if strings.Contains(addr, ":") {
						if conf.AddressV6 == "" {
							conf.AddressV6 = addr
						}
					} else {
						if conf.AddressV4 == "" {
							conf.AddressV4 = addr
						}
					}
				}
			case "listenport":
				if p, err := strconv.Atoi(val); err == nil {
					conf.ListenPort = p
				}
			case "dns":
				conf.DNS = val
			case "mtu":
				if m, err := strconv.Atoi(val); err == nil {
					conf.MTU = m
				}
			case "preup":
				if conf.PreUp != "" {
					conf.PreUp += "\n"
				}
				conf.PreUp += val
			case "postup":
				if conf.PostUp != "" {
					conf.PostUp += "\n"
				}
				conf.PostUp += val
			case "predown":
				if conf.PreDown != "" {
					conf.PreDown += "\n"
				}
				conf.PreDown += val
			case "postdown":
				if conf.PostDown != "" {
					conf.PostDown += "\n"
				}
				conf.PostDown += val
			case "table":
				// ignored
			}
		} else if currentPeer != nil {
			switch strings.ToLower(key) {
			case "publickey":
				currentPeer.PublicKey = val
			case "presharedkey":
				currentPeer.PresharedKey = val
			case "allowedips":
				currentPeer.AllowedIPs = val
			case "endpoint":
				currentPeer.Endpoint = val
			case "persistentkeepalive":
				if k, err := strconv.Atoi(val); err == nil {
					currentPeer.PersistentKeepalive = k
				}
			}
		}
	}
	if currentPeer != nil {
		conf.Peers = append(conf.Peers, *currentPeer)
	}

	if conf.PrivateKey == "" && conf.AddressV4 == "" && conf.AddressV6 == "" && len(conf.Peers) == 0 {
		return nil, fmt.Errorf("no recognizable WireGuard configuration found")
	}
	return conf, nil
}

// generateWGConf produces a wg0.conf formatted string for an interface and its peers.
func generateWGConf(iface *Interface, peers []Peer) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	if iface.AddressV4 != nil {
		if iface.AddressV6 != nil {
			sb.WriteString(fmt.Sprintf("Address = %s, %s\n", *iface.AddressV4, *iface.AddressV6))
		} else {
			sb.WriteString(fmt.Sprintf("Address = %s\n", *iface.AddressV4))
		}
	} else if iface.AddressV6 != nil {
		sb.WriteString(fmt.Sprintf("Address = %s\n", *iface.AddressV6))
	}
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", iface.ListenPort))
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", iface.PrivateKey))
	if iface.Dns != nil {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", *iface.Dns))
	}
	if iface.Mtu != nil {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", *iface.Mtu))
	}
	if iface.PreUp != nil {
		for _, line := range strings.Split(*iface.PreUp, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				sb.WriteString(fmt.Sprintf("PreUp = %s\n", line))
			}
		}
	}
	if iface.PostUp != nil {
		for _, line := range strings.Split(*iface.PostUp, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				sb.WriteString(fmt.Sprintf("PostUp = %s\n", line))
			}
		}
	}
	if iface.PreDown != nil {
		for _, line := range strings.Split(*iface.PreDown, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				sb.WriteString(fmt.Sprintf("PreDown = %s\n", line))
			}
		}
	}
	if iface.PostDown != nil {
		for _, line := range strings.Split(*iface.PostDown, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				sb.WriteString(fmt.Sprintf("PostDown = %s\n", line))
			}
		}
	}

	for _, p := range peers {
		sb.WriteString("\n[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.Pubkey))
		if p.Psk != nil {
			sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", *p.Psk))
		}
		var allowedIPs []string
		if p.Ipv4 != nil {
			allowedIPs = append(allowedIPs, *p.Ipv4)
		}
		if p.Ipv6 != nil {
			allowedIPs = append(allowedIPs, *p.Ipv6)
		}
		if len(allowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowedIPs, ", ")))
		}
	}

	return sb.String()
}
