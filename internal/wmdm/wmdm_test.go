package wmdm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TechTimCA/keystone-mdm/internal/pki"
	"github.com/TechTimCA/keystone-mdm/internal/store"
)

func newServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(filepath.Join(dir, "pki"), "Test Org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "k.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{PublicURL: "https://mdm.example.com", EnrollSecret: "s3cret", OrgName: "Test Org", CA: ca, Store: st, TrustProxyTLS: true}
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, body string) string {
	t.Helper()
	resp, err := http.Post(url, "application/soap+xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: status %d: %s", url, resp.StatusCode, b)
	}
	return string(b)
}

const sec = `<s:Header><a:MessageID>urn:uuid:1</a:MessageID><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:UsernameToken><wsse:Username>tim@example.com</wsse:Username><wsse:Password>PASS</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>`

func env(pass, body string) string {
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">` +
		strings.Replace(sec, "PASS", pass, 1) + `<s:Body>` + body + `</s:Body></s:Envelope>`
}

func TestEnrollAndManage(t *testing.T) {
	s, ts := newServer(t)

	disc := post(t, ts.URL+pathDiscovery, env("", `<Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment"><request><EmailAddress>tim@example.com</EmailAddress></request></Discover>`))
	if !strings.Contains(disc, "https://mdm.example.com/EnrollmentServer/Enrollment.svc") {
		t.Fatalf("discovery missing enrollment URL: %s", disc)
	}

	if out := post(t, ts.URL+pathPolicy, env("wrong", `<GetPolicies/>`)); !strings.Contains(out, "Fault") {
		t.Fatal("bad password should fault")
	}
	if out := post(t, ts.URL+pathPolicy, env("s3cret", `<GetPolicies/>`)); !strings.Contains(out, "GetPoliciesResponse") {
		t.Fatal("policy response missing")
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	rst := `<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` + base64.StdEncoding.EncodeToString(csr) + `</wsse:BinarySecurityToken>
<ac:AdditionalContext><ac:ContextItem Name="DeviceID"><ac:Value>DEV123</ac:Value></ac:ContextItem><ac:ContextItem Name="DeviceName"><ac:Value>FRONT-DESK</ac:Value></ac:ContextItem></ac:AdditionalContext>
</wst:RequestSecurityToken>`
	out := post(t, ts.URL+pathEnrollment, env("s3cret", rst))
	var resp struct {
		Token string `xml:"Body>RequestSecurityTokenResponseCollection>RequestSecurityTokenResponse>RequestedSecurityToken>BinarySecurityToken"`
	}
	if err := xml.Unmarshal([]byte(out), &resp); err != nil || resp.Token == "" {
		t.Fatalf("no provisioning doc: %v %s", err, out)
	}
	doc, _ := base64.StdEncoding.DecodeString(resp.Token)
	var wap struct {
		XMLName xml.Name `xml:"wap-provisioningdoc"`
	}
	if err := xml.Unmarshal(doc, &wap); err != nil {
		t.Fatalf("provisioning doc is not valid XML: %v", err)
	}
	if !strings.Contains(string(doc), "/ManagementServer/MDM.svc") {
		t.Fatal("provisioning doc missing management URL")
	}
	d, ok := s.Store.Device("DEV123")
	if !ok || d.Name != "FRONT-DESK" || d.CertThumb == "" {
		t.Fatalf("device not stored: %+v", d)
	}

	// First management session: device alerts, server sends inventory Gets.
	msg1 := `<SyncML xmlns="SYNCML:SYNCML1.2"><SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>1</SessionID><MsgID>1</MsgID>
<Target><LocURI>https://mdm.example.com/ManagementServer/MDM.svc</LocURI></Target><Source><LocURI>DEV123</LocURI></Source></SyncHdr>
<SyncBody><Alert><CmdID>2</CmdID><Data>1201</Data></Alert>
<Replace><CmdID>3</CmdID><Item><Source><LocURI>./DevInfo/Man</LocURI></Source><Data>Dell Inc.</Data></Item><Item><Source><LocURI>./DevInfo/Mod</LocURI></Source><Data>OptiPlex 7090</Data></Item></Replace><Final/></SyncBody></SyncML>`
	r1 := post(t, ts.URL+PathManagement, msg1)
	if !strings.Contains(r1, "<Get><CmdID>ks-") || !strings.Contains(r1, URIEncryption) {
		t.Fatalf("expected inventory Gets: %s", r1)
	}
	var parsed struct {
		Gets []struct {
			CmdID string `xml:"CmdID"`
		} `xml:"SyncBody>Get"`
	}
	if err := xml.Unmarshal([]byte(r1), &parsed); err != nil {
		t.Fatalf("response not valid XML: %v", err)
	}

	// Device answers the encryption Get.
	encID := ""
	for _, c := range s.Store.CommandsFor("DEV123", 100) {
		if c.LocURI == URIEncryption {
			encID = cmdIDPrefix + c.ID
		}
	}
	msg2 := `<SyncML xmlns="SYNCML:SYNCML1.2"><SyncHdr><SessionID>1</SessionID><MsgID>2</MsgID><Source><LocURI>DEV123</LocURI></Source></SyncHdr><SyncBody>
<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>` + encID + `</CmdRef><Cmd>Get</Cmd><Data>200</Data></Status>
<Results><CmdID>2</CmdID><CmdRef>` + encID + `</CmdRef><Item><Source><LocURI>` + URIEncryption + `</LocURI></Source><Data>1</Data></Item></Results><Final/></SyncBody></SyncML>`
	r2 := post(t, ts.URL+PathManagement, msg2)
	if strings.Contains(r2, "<Get>") {
		t.Fatalf("expected empty queue, got: %s", r2)
	}
	d, _ = s.Store.Device("DEV123")
	if d.Manufacturer != "Dell Inc." || Health(d)[0].State != "ok" {
		t.Fatalf("device not updated: %+v %+v", d, Health(d))
	}

	// Unknown devices are refused.
	resp2, _ := http.Post(ts.URL+PathManagement, "application/vnd.syncml.dm+xml", strings.NewReader(strings.Replace(msg1, "DEV123", "NOPE", 1)))
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown device got %d", resp2.StatusCode)
	}
}
