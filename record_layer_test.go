package qtls

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type exportedKey struct {
	typ           string // "read" or "write"
	encLevel      EncryptionLevel
	suite         *CipherSuiteTLS13
	trafficSecret []byte
}

func compareExportedKeys(t *testing.T, k1, k2 *exportedKey) {
	if k1.encLevel != k2.encLevel || k1.suite.ID != k2.suite.ID || !bytes.Equal(k1.trafficSecret, k2.trafficSecret) {
		t.Fatal("mismatching keys")
	}
}

type recordLayer struct {
	in  <-chan []byte
	out chan<- interface{}
}

func (r *recordLayer) SetReadKey(encLevel EncryptionLevel, suite *CipherSuiteTLS13, trafficSecret []byte) {
	r.out <- &exportedKey{typ: "read", encLevel: encLevel, suite: suite, trafficSecret: trafficSecret}
}
func (r *recordLayer) SetWriteKey(encLevel EncryptionLevel, suite *CipherSuiteTLS13, trafficSecret []byte) {
	r.out <- &exportedKey{typ: "write", encLevel: encLevel, suite: suite, trafficSecret: trafficSecret}
}
func (r *recordLayer) ReadHandshakeMessage() ([]byte, error) { return <-r.in, nil }
func (r *recordLayer) WriteRecord(b []byte) (int, error)     { r.out <- b; return len(b), nil }
func (r *recordLayer) SendAlert(uint8)                       {}

type unusedConn struct{}

var _ net.Conn = &unusedConn{}

func (unusedConn) Read([]byte) (int, error)         { panic("unexpected call to Read()") }
func (unusedConn) Write([]byte) (int, error)        { panic("unexpected call to Write()") }
func (unusedConn) Close() error                     { return nil }
func (unusedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (unusedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (unusedConn) SetDeadline(time.Time) error      { return nil }
func (unusedConn) SetReadDeadline(time.Time) error  { return nil }
func (unusedConn) SetWriteDeadline(time.Time) error { return nil }

func TestAlternativeRecordLayer(t *testing.T) {
	sIn := make(chan []byte, 10)
	sOut := make(chan interface{}, 10)
	defer close(sOut)
	cIn := make(chan []byte, 10)
	cOut := make(chan interface{}, 10)
	defer close(cOut)

	serverKeyChan := make(chan *exportedKey, 4) // see server loop for the order in which keys are provided
	// server side
	go func() {
		var counter int
		for {
			c, ok := <-sOut
			if !ok {
				return
			}
			switch counter {
			case 0:
				if c.([]byte)[0] != typeServerHello {
					t.Errorf("expected ServerHello")
				}
			case 1:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "read" || keyEv.encLevel != EncryptionHandshake {
					t.Errorf("expected the handshake read key")
				}
				serverKeyChan <- keyEv
			case 2:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "write" || keyEv.encLevel != EncryptionHandshake {
					t.Errorf("expected the handshake write key")
				}
				serverKeyChan <- keyEv
			case 3:
				if c.([]byte)[0] != typeEncryptedExtensions {
					t.Errorf("expected EncryptedExtensions")
				}
			case 4:
				if c.([]byte)[0] != typeCertificate {
					t.Errorf("expected Certificate")
				}
			case 5:
				if c.([]byte)[0] != typeCertificateVerify {
					t.Errorf("expected CertificateVerify")
				}
			case 6:
				if c.([]byte)[0] != typeFinished {
					t.Errorf("expected Finished")
				}
			case 7:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "write" || keyEv.encLevel != EncryptionApplication {
					t.Errorf("expected the application write key")
				}
				serverKeyChan <- keyEv
			case 8:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "read" || keyEv.encLevel != EncryptionApplication {
					t.Errorf("expected the application read key")
				}
				serverKeyChan <- keyEv
			default:
				t.Error("didn't expect any more events")
			}
			counter++
			if b, ok := c.([]byte); ok {
				cIn <- b
			}
		}
	}()

	// client side
	go func() {
		var counter int
		for {
			c, ok := <-cOut
			if !ok {
				return
			}
			switch counter {
			case 0:
				if c.([]byte)[0] != typeClientHello {
					t.Errorf("expected ClientHello")
				}
			case 1:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "write" || keyEv.encLevel != EncryptionHandshake {
					t.Errorf("expected the handshake write key")
				}
				compareExportedKeys(t, <-serverKeyChan, keyEv)
			case 2:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "read" || keyEv.encLevel != EncryptionHandshake {
					t.Errorf("expected the handshake read key")
				}
				compareExportedKeys(t, <-serverKeyChan, keyEv)
			case 3:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "read" || keyEv.encLevel != EncryptionApplication {
					t.Errorf("expected the application read key")
				}
				compareExportedKeys(t, <-serverKeyChan, keyEv)
			case 4:
				if c.([]byte)[0] != typeFinished {
					t.Errorf("expected Finished")
				}
			case 5:
				keyEv := c.(*exportedKey)
				if keyEv.typ != "write" || keyEv.encLevel != EncryptionApplication {
					t.Errorf("expected the application write key")
				}
				compareExportedKeys(t, <-serverKeyChan, keyEv)
			default:
				t.Error("didn't expect any more events")
			}
			counter++
			if b, ok := c.([]byte); ok {
				sIn <- b
			}
		}
	}()

	errChan := make(chan error)
	go func() {
		extraConf := &ExtraConfig{
			AlternativeRecordLayer: &recordLayer{in: sIn, out: sOut},
		}
		tlsConn := Server(&unusedConn{}, testConfig, extraConf)
		defer tlsConn.Close()
		errChan <- tlsConn.Handshake()
	}()

	extraConf := &ExtraConfig{
		AlternativeRecordLayer: &recordLayer{in: cIn, out: cOut},
	}
	tlsConn := Client(&unusedConn{}, testConfig, extraConf)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %s", err)
	}

	select {
	case <-time.After(500 * time.Millisecond):
		t.Fatal("server timed out")
	case err := <-errChan:
		if err != nil {
			t.Fatalf("server handshake failed: %s", err)
		}
	}
}
