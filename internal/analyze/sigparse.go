package analyze

import (
	"crypto/x509"
	"encoding/binary"
	"slices"
)

// extractCerts pulls X.509 certificates out of a PKCS#7/CMS blob. Rather
// than walking the (often BER, indefinite-length) CMS structure we look for
// DER SEQUENCE headers and let x509 validate each candidate, which is both
// simpler and tolerant of the encodings Apple and Microsoft emit.
func extractCerts(blob []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for i := 0; i+8 < len(blob); i++ {
		if blob[i] != 0x30 || blob[i+1] != 0x82 || blob[i+4] != 0x30 {
			continue
		}
		n := int(binary.BigEndian.Uint16(blob[i+2:]))
		if i+4+n > len(blob) || n < 200 {
			continue
		}
		c, err := x509.ParseCertificate(blob[i : i+4+n])
		if err != nil {
			continue
		}
		certs = append(certs, c)
		i += 3 + n
	}
	return certs
}

// signerCert picks the end-entity code-signing certificate.
func signerCert(certs []*x509.Certificate) *x509.Certificate {
	var fallback *x509.Certificate
	for _, c := range certs {
		if c.IsCA {
			continue
		}
		if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
			return c
		}
		if fallback == nil && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
			fallback = c
		}
	}
	return fallback
}

func fillSigner(sig *Signature, blob []byte) {
	c := signerCert(extractCerts(blob))
	if c == nil {
		return
	}
	sig.Signer = c.Subject.CommonName
	if sig.Signer == "" && len(c.Subject.Organization) > 0 {
		sig.Signer = c.Subject.Organization[0]
	}
	sig.Issuer = c.Issuer.CommonName
	sig.NotAfter = c.NotAfter.Format("2006-01-02")
}
