package encryption

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// NewClient creates a client-side VLESS encryption instance.
// A nil instance with nil error means encryption is disabled.
func NewClient(encryption string) (*ClientInstance, error) {
	switch encryption {
	case "", "none":
		return nil, nil
	}
	if s := strings.Split(encryption, "."); len(s) >= 4 && s[0] == "mlkem768x25519plus" {
		var xorMode uint32
		switch s[1] {
		case "native":
		case "xorpub":
			xorMode = 1
		case "random":
			xorMode = 2
		default:
			return nil, fmt.Errorf("invalid vless encryption value: %s", encryption)
		}
		var seconds uint32
		switch s[2] {
		case "1rtt":
		case "0rtt":
			seconds = 1
		default:
			return nil, fmt.Errorf("invalid vless encryption value: %s", encryption)
		}
		var nfsPKeysBytes [][]byte
		var paddings []string
		for _, r := range s[3:] {
			if len(r) < 20 {
				paddings = append(paddings, r)
				continue
			}
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, fmt.Errorf("invalid vless encryption value: %s", encryption)
			}
			if len(b) != X25519PasswordSize && len(b) != MLKEM768ClientLength {
				return nil, fmt.Errorf("invalid vless encryption value: %s", encryption)
			}
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		client := &ClientInstance{}
		if err := client.Init(nfsPKeysBytes, xorMode, seconds, strings.Join(paddings, ".")); err != nil {
			return nil, fmt.Errorf("failed to use encryption: %w", err)
		}
		return client, nil
	}
	return nil, fmt.Errorf("invalid vless encryption value: %s", encryption)
}
