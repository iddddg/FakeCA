package lab

import "fmt"

const CurrentBundleVersion = 2

// BundleFiles names the files by role. Version 1 used chain.pem for the leaf
// and intermediates together; never infer its meaning from a filename alone.
type BundleFiles struct {
	Certificate, PrivateKey, IssuingCA, FullChain, Intermediates, Root, FullChainWithRoot string
}

func BundleFilesForVersion(version int) (BundleFiles, error) {
	switch version {
	case 1:
		return BundleFiles{"leaf.pem", "leaf.key", "ca.pem", "chain.pem", "issuers.pem", "root.pem", "chain-with-root.pem"}, nil
	case CurrentBundleVersion:
		return BundleFiles{"cert.pem", "private.key", "issuing-ca.pem", "fullchain.pem", "intermediates.pem", "root.pem", "fullchain-with-root.pem"}, nil
	default:
		return BundleFiles{}, fmt.Errorf("不支持的证书包报告版本：%d", version)
	}
}

func (f BundleFiles) Names() []string {
	return []string{f.Certificate, f.PrivateKey, f.IssuingCA, f.FullChain, f.Intermediates, f.Root, f.FullChainWithRoot, "identity.p12", "password.txt", "report.json"}
}
