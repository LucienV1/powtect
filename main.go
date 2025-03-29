package powtect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	//"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hashicorp/go-msgpack/v2/codec"
)

//go:embed index.html
var static []byte

var DefaultWhitelist = []string{}
var DefaultCookiePrefix string = "_powtect"
var DefaultTTL int = 3600
var DefaultLevel int = 4

func init() {
	caddy.RegisterModule(Powtect{})
	httpcaddyfile.RegisterHandlerDirective("powtect", parseCaddyfileHandler)
	httpcaddyfile.RegisterDirectiveOrder("powtect", httpcaddyfile.After, "encode")
}

type Cookie struct {
	Unverified bool   `msgpack:"unverified,omitempty"`
	Solution   string `msgpack:"solution,omitempty"`
	Hash       string `msgpack:"hash,omitempty"`
	Created    int64  `msgpack:"created,omitempty"`
	Prefix     string `msgpack:"prefix,omitempty"`
}

type Powtect struct {
	Key          []byte   `json:"token,omitempty"`
	Level        int      `json:"level,omitempty"`
	Whitelist    []string `json:"whitelist,omitempty"`
	CookiePrefix string   `json:"cookieprefix,omitempty"`
	TTL          int      `json:"ttl,omitempty"`
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p Powtect
	err := p.UnmarshalCaddyfile(h.Dispenser)
	return p, err
}

func (p Powtect) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.powtect",
		New: func() caddy.Module { return new(Powtect) },
	}
}

func (p *Powtect) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	p.CookiePrefix = DefaultCookiePrefix
	p.Level = DefaultLevel
	p.TTL = DefaultTTL
	p.Whitelist = DefaultWhitelist
	p.Key = nil
	var err error = nil
	d.Next()
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "cookieprefix":
			{
				d.Next()
				p.CookiePrefix = d.Val()
				continue
			}
		case "level":
			{
				d.Next()
				p.Level, err = strconv.Atoi(d.Val())
				if err != nil {
					return err
				}
				if p.Level > 64 {
					return d.Errf("level must be less than 64")
				}
				continue
			}
		case "ttl":
			{
				d.Next()
				p.TTL, err = strconv.Atoi(d.Val())
				if err != nil {
					return err
				}
				continue
			}
		case "key":
			{
				d.Next()
				p.Key = []byte(d.Val())
				if len(p.Key) != 32 {
					//logPrintf("Powtect: Key must be 32 bytes, padding or truncating")
					if len(p.Key) > 32 {
						p.Key = p.Key[:32]
					} else {
						for len(p.Key) < 32 {
							p.Key = append(p.Key, 0)
						}
					}
				}
				continue
			}
		case "whitelist":
			{
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					p.Whitelist = append(p.Whitelist, d.Val())
					continue
				}
			}
		default:
			{
				return d.Errf("unknown property '%s'", d.Val())
			}
		}
	}

	if p.Key == nil {
		pk := make([]byte, 32)
		_, err = rand.Read(pk)
		if err != nil {
			return err
		}
		p.Key = pk
	}

	return nil
}

func (p Powtect) ServeHTTP(r http.ResponseWriter, d *http.Request, next caddyhttp.Handler) error {
	//logPrintln("Powtect: ServeHTTP")
	var wh []string
	var cn string
	wh = p.Whitelist
	cn = p.CookiePrefix

	//logPrintln("Powtect: Checking whitelist")
	if slices.Contains(wh, d.UserAgent()) {
		err := next.ServeHTTP(r, d)
		return err
	}
	//logPrintln("Powtect: Not in whitelist")
	//logPrintln("Powtect: Checking cookie")
	cv, err := d.Cookie(cn + "_main")
	if err == http.ErrNoCookie {

		//logPrintln("Powtect: No cookie, creating new")
		err = createnew(r, d, p)
		return err

	} else if err != nil {
		//logPrintln("Powtect: Error reading cookie")
		return err
	}

	//logPrintln("Powtect: Cookie found")
	//logPrintln("Powtect: Decrypting cookie")

	c, err := decrypt(p.Key, cv.Value)
	if err != nil {
		//logPrintf("Powtect: Error decrypting cookie, creating new: %v", err)
		err = createnew(r, d, p)
		return err
	}

	if time.Now().Unix()-c.Created > int64(p.TTL) {
		//logPrintln("Powtect: Cookie expired, creating new")
		err = createnew(r, d, p)
		return err
	}

	//logPrintln("Powtect: Checking cookie and solution")
	if c.Unverified && d.Header.Get("X-Powtect-Solution") == "" {

		//logPrintln("Powtect: Unverified and no solution")

		r.Header().Add("Content-Type", "text/html")
		r.Header().Add("Content-Length", strconv.Itoa(len(static)))
		r.Header().Add("Cache-Control", "no-cache")
		r.Header().Add("X-Powtect-Level", strconv.Itoa(p.Level))
		r.Header().Add("X-Powtect-Prefix", c.Prefix)

		//logPrintln("Powtect: headers set, writing static")

		r.WriteHeader(http.StatusOK)
		_, err = r.Write(static)
		return err

	} else if c.Unverified && d.Header.Get("X-Powtect-Solution") != "" && d.Header.Get("X-Powtect-Hash") != "" {

		c.Solution = d.Header.Get("X-Powtect-Solution")
		c.Hash = d.Header.Get("X-Powtect-Hash")

		//logPrintln("Powtect: Unverified and solution")

		hash := sha256.New()
		hash.Write([]byte(c.Solution))

		i := 0
		zero := ""
		for i < p.Level {
			zero += "0"
			i++
		}

		if len(c.Prefix) > len(c.Solution) {

			//logPrintln("Powtect: Prefix longer than solution")

			r.Header().Add("Content-Type", "text/html")
			r.Header().Add("Content-Length", strconv.Itoa(len(static)))
			r.Header().Add("Cache-Control", "no-cache")
			r.Header().Add("X-Powtect-Level", strconv.Itoa(p.Level))
			r.Header().Add("X-Powtect-Prefix", c.Prefix)

			//logPrintln("Powtect: headers set, writing static")
			r.WriteHeader(http.StatusOK)
			_, err = r.Write(static)
			return err
		}
		hb, err := hex.DecodeString(c.Hash)
		if err != nil {
			//logPrintf("Powtect: Error decoding hash: %v", err)
			return err
		}

		//logPrintln("Powtect: Checking hash and prefix")
		if subtle.ConstantTimeCompare(hash.Sum(nil), hb) == 1 && strings.HasPrefix(c.Hash, zero) && c.Prefix == c.Solution[:len(c.Prefix)] {

			//logPrintln("Powtect: Hash and prefix match")
			c.Unverified = false
			c.Solution = d.Header.Get("X-Powtect-Solution")
			c.Created = time.Now().Unix()

			sec, err := encrypt(p.Key, c)
			//logPrintln("Powtect: Encrypting cookie")

			if err != nil {
				return err
			}

			//logPrintln("Powtect: Setting cookie")
			b64 := base64.StdEncoding.EncodeToString(sec)
			http.SetCookie(r, &http.Cookie{
				Name:     cn + "_main",
				Value:    b64,
				MaxAge:   p.TTL,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})

			//logPrintln("Powtect: Cookie set, forwarding request")

			err = next.ServeHTTP(r, d)
			return err

		}

	} else if !c.Unverified {

		//logPrintln("Powtect: Verified")

		i := 0
		zero := ""
		for i < p.Level {
			zero += "0"
			i++
		}

		if strings.HasPrefix(c.Hash, zero) {

			//logPrintln("Powtect: Hash check passed")
			err = next.ServeHTTP(r, d)
			return err
		}

		//logPrintln("Powtect: Hash check failed, creating new")
		err = createnew(r, d, p)
		return err

	}

	return nil
}

func createnew(r http.ResponseWriter, _ *http.Request, p Powtect) error {
	var cn string
	var ttl int
	cn = p.CookiePrefix
	ttl = p.TTL
	//logPrintln("Powtect: Creating new cookie")

	pf := make([]byte, 16)
	_, err := rand.Read(pf)
	if err != nil {
		return err
	}
	prefix := base64.RawStdEncoding.EncodeToString(pf)

	//logPrintln("Powtect: Encrypting cookie")

	sec, err := encrypt(p.Key, Cookie{
		Unverified: true,
		Prefix:     prefix,
		Created:    time.Now().Unix(),
	})
	if err != nil {
		return err
	}

	//logPrintln("Powtect: Setting cookie")

	b64 := base64.StdEncoding.EncodeToString(sec)
	http.SetCookie(r, &http.Cookie{
		Name:     cn + "_main",
		Value:    b64,
		MaxAge:   ttl,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	//logPrintln("Powtect: Cookie set, writing static")

	r.Header().Set("Content-Type", "text/html")
	r.Header().Set("Content-Length", strconv.Itoa(len(static)))
	r.Header().Set("Cache-Control", "no-cache")
	r.Header().Set("X-Powtect-Level", strconv.Itoa(p.Level))
	r.Header().Set("X-Powtect-Prefix", prefix)

	r.WriteHeader(http.StatusOK)
	_, err = r.Write(static)
	return err
}

func encrypt(key []byte, c Cookie) ([]byte, error) {
	//logPrintln("Powtect: Encrypting cookie")
	out := make([]byte, 0)
	enc := codec.NewEncoderBytes(&out, &codec.MsgpackHandle{})
	enc.Encode(c)

	block, err := aes.NewCipher(key)
	if err != nil {
		//logPrintf("Powtect: Error creating cipher: %v", err)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//logPrintf("Powtect: Error creating GCM: %v", err)
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		//logPrintf("Powtect: Error creating nonce: %v", err)
		return nil, err
	}
	sec := gcm.Seal(nonce, nonce, out, nil)
	//logPrintln("Powtect: Cookie encrypted")

	return sec, nil
}

func decrypt(key []byte, b64 string) (Cookie, error) {
	var c Cookie
	//logPrintln("Powtect: Decrypting cookie")

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		//logPrintf("Powtect: Error decoding cookie: %v", err)
		return Cookie{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		//logPrintf("Powtect: Error creating cipher: %v", err)
		return Cookie{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//logPrintf("Powtect: Error creating GCM: %v", err)
		return Cookie{}, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		//logPrintf("Powtect: Error decrypting cookie: %v", err)
		return Cookie{}, err
	}
	dec := codec.NewDecoderBytes(plain, &codec.MsgpackHandle{})
	err = dec.Decode(&c)
	if err != nil {
		//logPrintf("Powtect: Error decoding cookie: %v", err)
		return Cookie{}, err
	}
	//logPrintln("Powtect: Cookie decrypted")
	return c, nil
}
