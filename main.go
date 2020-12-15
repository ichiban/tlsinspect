package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/pflag"
)

func main() {
	var (
		insecure  bool
		userAgent string
		timeout   time.Duration
	)
	pflag.BoolVarP(&insecure, "insecure", "k", false, "ignore TLS verification error")
	pflag.StringVarP(&userAgent, "user-agent", "A", "", "user agent")
	pflag.DurationVarP(&timeout, "timeout", "t", 5*time.Second, "timeout")
	pflag.Parse()

	client := http.Client{
		Timeout: timeout,
	}

	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	results := make(map[string]Result, len(pflag.Args()))
	for _, target := range pflag.Args() {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			results[target] = Result{
				Error: fmt.Errorf("failed to create request: %w", err).Error(),
			}
			continue
		}

		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			results[target] = Result{
				Error: fmt.Errorf("failed to get: %w", err).Error(),
			}
			continue
		}

		n, err := io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			results[target] = Result{
				Error: fmt.Errorf("failed to discard body: %w", err).Error(),
			}
			continue
		}
		if err = resp.Body.Close(); err != nil {
			results[target] = Result{
				Error: fmt.Errorf("failed to close body: %w", err).Error(),
			}
			continue
		}

		result := Result{
			Status:        resp.Status,
			ContentLength: n,
		}

		if resp.TLS != nil {
			result.TLS = newState(resp.TLS)
		}

		results[target] = result
	}

	b, _ := json.Marshal(results)
	fmt.Print(string(b))
}

type Result struct {
	Status        string `json:",omitempty"`
	ContentLength int64  `json:",omitempty"`
	Error         string `json:",omitempty"`
	TLS           *State `json:",omitempty"`
}

type State struct {
	Version          string
	CipherSuite      string
	ServerName       string
	PeerCertificates []certificate
	VerifiedChains   [][]certificate
}

func newState(cs *tls.ConnectionState) *State {
	s := State{
		Version: func() string {
			v := cs.Version
			switch v {
			case tls.VersionTLS10:
				return "TLS 1.0"
			case tls.VersionTLS11:
				return "TLS 1.1"
			case tls.VersionTLS12:
				return "TLS 1.2"
			case tls.VersionTLS13:
				return "TLS 1.3"
			default:
				return fmt.Sprintf("UNKNOWN (0x%04x)", v)
			}
		}(),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ServerName:  cs.ServerName,
	}

	s.PeerCertificates = make([]certificate, len(cs.PeerCertificates))
	for i, pc := range cs.PeerCertificates {
		s.PeerCertificates[i] = newCertificate(pc)
	}

	s.VerifiedChains = make([][]certificate, len(cs.VerifiedChains))
	for i, vc := range cs.VerifiedChains {
		chain := make([]certificate, len(vc))
		for i, c := range vc {
			chain[i] = newCertificate(c)
		}
		s.VerifiedChains[i] = chain
	}

	return &s
}

type certificate struct {
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	Version            int
	SerialNumber       string
	Issuer             name
	Subject            name
}

func newCertificate(c *x509.Certificate) certificate {
	return certificate{
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		Version:            c.Version,
		SerialNumber:       c.SerialNumber.String(),
		Issuer: name{
			Country:            c.Issuer.Country,
			Organization:       c.Issuer.Organization,
			OrganizationalUnit: c.Issuer.OrganizationalUnit,
			Locality:           c.Issuer.Locality,
			Province:           c.Issuer.Province,
			StreetAddress:      c.Issuer.StreetAddress,
			PostalCode:         c.Issuer.PostalCode,
			SerialNumber:       c.Issuer.SerialNumber,
			CommonName:         c.Issuer.CommonName,
		},
		Subject: name{
			Country:            c.Subject.Country,
			Organization:       c.Subject.Organization,
			OrganizationalUnit: c.Subject.OrganizationalUnit,
			Locality:           c.Subject.Locality,
			Province:           c.Subject.Province,
			StreetAddress:      c.Subject.StreetAddress,
			PostalCode:         c.Subject.PostalCode,
			SerialNumber:       c.Subject.SerialNumber,
			CommonName:         c.Subject.CommonName,
		},
	}
}

type name struct {
	Country            []string `json:",omitempty"`
	Organization       []string `json:",omitempty"`
	OrganizationalUnit []string `json:",omitempty"`
	Locality           []string `json:",omitempty"`
	Province           []string `json:",omitempty"`
	StreetAddress      []string `json:",omitempty"`
	PostalCode         []string `json:",omitempty"`
	SerialNumber       string   `json:",omitempty"`
	CommonName         string   `json:",omitempty"`
}
