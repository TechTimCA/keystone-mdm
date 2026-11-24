// Package wmdm implements the server side of Windows' built-in MDM client:
// MS-MDE2 enrollment (discovery, policy, enrollment) and the OMA-DM
// (SyncML) management session. Reference: Microsoft's [MS-MDE2] and
// [MS-MDM] open specifications.
package wmdm

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TechTimCA/keystone-mdm/internal/pki"
	"github.com/TechTimCA/keystone-mdm/internal/store"
)

const (
	ProviderID = "KeystoneMDM"

	pathDiscovery  = "/EnrollmentServer/Discovery.svc"
	pathPolicy     = "/EnrollmentServer/Policy.svc"
	pathEnrollment = "/EnrollmentServer/Enrollment.svc"
	PathManagement = "/ManagementServer/MDM.svc"
)

// Server holds the enrollment and management handlers.
type Server struct {
	PublicURL     string // e.g. https://enterpriseenrollment.example.com (no trailing slash)
	EnrollSecret  string // password typed on the PC during enrollment
	OrgName       string
	CA            *pki.CA
	Store         *store.Store
	TrustProxyTLS bool // true when TLS ends at a reverse proxy (client certs not visible)
}

// Register mounts all Windows MDM endpoints on mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc(pathDiscovery, s.discovery)
	mux.HandleFunc(pathPolicy, s.policy)
	mux.HandleFunc(pathEnrollment, s.enroll)
	mux.HandleFunc(PathManagement, s.manage)
}

// soapIn captures the parts of incoming SOAP messages we need.
// Tags without namespaces match any namespace in encoding/xml.
type soapIn struct {
	Header struct {
		MessageID string `xml:"MessageID"`
		Security  struct {
			UsernameToken struct {
				Username string `xml:"Username"`
				Password string `xml:"Password"`
			} `xml:"UsernameToken"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Discover struct {
			Request struct {
				EmailAddress string `xml:"EmailAddress"`
			} `xml:"request"`
		} `xml:"Discover"`
		RST struct {
			BinarySecurityToken string `xml:"BinarySecurityToken"`
			AdditionalContext   struct {
				Items []struct {
					Name  string `xml:"Name,attr"`
					Value string `xml:"Value"`
				} `xml:"ContextItem"`
			} `xml:"AdditionalContext"`
		} `xml:"RequestSecurityToken"`
	} `xml:"Body"`
}

func readSOAP(r *http.Request) (*soapIn, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var in soapIn
	if err := xml.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

func writeSOAP(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	io.WriteString(w, body)
}

// discovery tells Windows where the policy and enrollment services live.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet { // Windows probes with GET first
		w.WriteHeader(http.StatusOK)
		return
	}
	in, err := readSOAP(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Printf("wmdm: discovery from %s for %q", r.RemoteAddr, in.Body.Discover.Request.EmailAddress)
	writeSOAP(w, fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse</a:Action>
<a:RelatesTo>%s</a:RelatesTo>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
<DiscoverResult>
<AuthPolicy>OnPremise</AuthPolicy>
<EnrollmentVersion>4.0</EnrollmentVersion>
<EnrollmentPolicyServiceUrl>%s</EnrollmentPolicyServiceUrl>
<EnrollmentServiceUrl>%s</EnrollmentServiceUrl>
</DiscoverResult>
</DiscoverResponse>
</s:Body>
</s:Envelope>`, x(in.Header.MessageID), x(s.PublicURL+pathPolicy), x(s.PublicURL+pathEnrollment)))
}

// checkCreds validates the enrollment password (OnPremise auth).
func (s *Server) checkCreds(in *soapIn) bool {
	got := in.Header.Security.UsernameToken.Password
	return s.EnrollSecret != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.EnrollSecret)) == 1
}

// policy returns the certificate request policy (key size, hash).
func (s *Server) policy(w http.ResponseWriter, r *http.Request) {
	in, err := readSOAP(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.checkCreds(in) {
		log.Printf("wmdm: policy request with bad enrollment password from %s", r.RemoteAddr)
		writeSOAP(w, soapFault(in.Header.MessageID, "s:Authentication", "Wrong enrollment password."))
		return
	}
	writeSOAP(w, fmt.Sprintf(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
<a:RelatesTo>%s</a:RelatesTo>
</s:Header>
<s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
<response>
<policyID/>
<policyFriendlyName xsi:nil="true"/>
<nextUpdateHours xsi:nil="true"/>
<policiesNotChanged xsi:nil="true"/>
<policies>
<policy>
<policyOIDReference>0</policyOIDReference>
<cAs xsi:nil="true"/>
<attributes>
<commonName>KeystoneDevice</commonName>
<policySchema>3</policySchema>
<certificateValidity>
<validityPeriodSeconds>31536000</validityPeriodSeconds>
<renewalPeriodSeconds>2592000</renewalPeriodSeconds>
</certificateValidity>
<permission><enroll>true</enroll><autoEnroll>false</autoEnroll></permission>
<privateKeyAttributes>
<minimalKeyLength>2048</minimalKeyLength>
<keySpec xsi:nil="true"/>
<keyUsageProperty xsi:nil="true"/>
<permissions xsi:nil="true"/>
<algorithmOIDReference xsi:nil="true"/>
<cryptoProviders xsi:nil="true"/>
</privateKeyAttributes>
<revision><majorRevision>101</majorRevision><minorRevision>0</minorRevision></revision>
<supersededPolicies xsi:nil="true"/>
<privateKeyFlags xsi:nil="true"/>
<subjectNameFlags xsi:nil="true"/>
<enrollmentFlags xsi:nil="true"/>
<generalFlags xsi:nil="true"/>
<hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
<rARequirements xsi:nil="true"/>
<keyArchivalAttributes xsi:nil="true"/>
<extensions xsi:nil="true"/>
</attributes>
</policy>
</policies>
</response>
<cAs xsi:nil="true"/>
<oIDs>
<oID><value>2.16.840.1.101.3.4.2.1</value><group>1</group><oIDReferenceID>0</oIDReferenceID><defaultName>szOID_NIST_sha256</defaultName></oID>
</oIDs>
</GetPoliciesResponse>
</s:Body>
</s:Envelope>`, x(in.Header.MessageID)))
}

// enroll signs the PC's CSR and returns the provisioning document that
// installs our CA, the device certificate and the DM account.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	in, err := readSOAP(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.checkCreds(in) {
		log.Printf("wmdm: enrollment with bad password from %s", r.RemoteAddr)
		writeSOAP(w, soapFault(in.Header.MessageID, "s:Authentication", "Wrong enrollment password."))
		return
	}
	ctx := map[string]string{}
	for _, it := range in.Body.RST.AdditionalContext.Items {
		ctx[it.Name] = strings.TrimSpace(it.Value)
	}
	deviceID := ctx["DeviceID"]
	if deviceID == "" {
		writeSOAP(w, soapFault(in.Header.MessageID, "s:Receiver", "Missing DeviceID."))
		return
	}
	csrDER, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(in.Body.RST.BinarySecurityToken), ""))
	if err != nil {
		writeSOAP(w, soapFault(in.Header.MessageID, "s:Receiver", "Bad certificate request."))
		return
	}
	cert, err := s.CA.SignDeviceCSR(csrDER, deviceID)
	if err != nil {
		log.Printf("wmdm: sign CSR for %s: %v", deviceID, err)
		writeSOAP(w, soapFault(in.Header.MessageID, "s:Receiver", "Could not issue certificate."))
		return
	}
	thumb := pki.Thumbprint(cert)
	user := in.Header.Security.UsernameToken.Username
	if err := s.Store.UpsertDevice(deviceID, func(d *store.Device) {
		d.HWDevID = ctx["HWDevID"]
		if n := ctx["DeviceName"]; n != "" {
			d.Name = n
		}
		if v := ctx["OSVersion"]; v != "" {
			d.OSVersion = v
		}
		d.EnrolledBy = user
		d.CertThumb = thumb
		d.EnrolledAt = time.Now().UTC()
		d.LastSeen = d.EnrolledAt
		d.Props["_inventoryAt"] = d.EnrolledAt.Format(time.RFC3339)
	}); err != nil {
		log.Printf("wmdm: save device: %v", err)
	}
	if err := s.Store.Enqueue(InventoryCommands(deviceID)...); err != nil {
		log.Printf("wmdm: queue inventory: %v", err)
	}
	log.Printf("wmdm: enrolled %s (%s) by %q", deviceID, ctx["DeviceName"], user)

	doc := s.provisioningDoc(deviceID, cert.Raw, thumb, ctx["DeviceName"])
	now := time.Now().UTC()
	writeSOAP(w, fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
<a:RelatesTo>%s</a:RelatesTo>
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<u:Timestamp u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp>
</o:Security>
</s:Header>
<s:Body>
<RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<RequestSecurityTokenResponse>
<TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
<DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>
<RequestedSecurityToken>
<BinarySecurityToken ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">%s</BinarySecurityToken>
</RequestedSecurityToken>
<RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
</RequestSecurityTokenResponse>
</RequestSecurityTokenResponseCollection>
</s:Body>
</s:Envelope>`, x(in.Header.MessageID), now.Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		base64.StdEncoding.EncodeToString([]byte(doc))))
}

// provisioningDoc is the wap-provisioningdoc Windows applies after enrollment.
// Poll schedule: every 15 min for the first 2 hours, then every 60 min.
func (s *Server) provisioningDoc(deviceID string, certDER []byte, thumb, name string) string {
	caThumb := pki.Thumbprint(s.CA.Cert)
	return fmt.Sprintf(`<wap-provisioningdoc version="1.1">
<characteristic type="CertificateStore">
<characteristic type="Root"><characteristic type="System">
<characteristic type="%s"><parm name="EncodedCertificate" value="%s"/></characteristic>
</characteristic></characteristic>
<characteristic type="My"><characteristic type="System">
<characteristic type="%s"><parm name="EncodedCertificate" value="%s"/></characteristic>
<characteristic type="PrivateKeyContainer"/>
</characteristic></characteristic>
</characteristic>
<characteristic type="APPLICATION">
<parm name="APPID" value="w7"/>
<parm name="PROVIDER-ID" value="%s"/>
<parm name="NAME" value="%s"/>
<parm name="ADDR" value="%s"/>
<parm name="CONNRETRYFREQ" value="6"/>
<parm name="INITIALBACKOFFTIME" value="30000"/>
<parm name="MAXBACKOFFTIME" value="120000"/>
<parm name="BACKCOMPATRETRYDISABLED"/>
<parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml"/>
<parm name="SSLCLIENTCERTSEARCHCRITERIA" value="Subject=CN%%3D%s&amp;Stores=My%%5CSystem"/>
<characteristic type="APPAUTH">
<parm name="AAUTHLEVEL" value="CLIENT"/><parm name="AAUTHTYPE" value="DIGEST"/>
<parm name="AAUTHSECRET" value="unused"/><parm name="AAUTHDATA" value="bm9uY2U="/>
</characteristic>
<characteristic type="APPAUTH">
<parm name="AAUTHLEVEL" value="APPSRV"/><parm name="AAUTHTYPE" value="DIGEST"/>
<parm name="AAUTHNAME" value="unused"/><parm name="AAUTHSECRET" value="unused"/><parm name="AAUTHDATA" value="bm9uY2U="/>
</characteristic>
</characteristic>
<characteristic type="DMClient"><characteristic type="Provider"><characteristic type="%s">
<parm name="EntDMID" value="%s" datatype="string"/>
<parm name="EntDeviceName" value="%s" datatype="string"/>
<characteristic type="Poll">
<parm name="NumberOfFirstRetries" value="8" datatype="integer"/>
<parm name="IntervalForFirstSetOfRetries" value="15" datatype="integer"/>
<parm name="NumberOfSecondRetries" value="0" datatype="integer"/>
<parm name="IntervalForSecondSetOfRetries" value="60" datatype="integer"/>
<parm name="NumberOfRemainingScheduledRetries" value="0" datatype="integer"/>
<parm name="IntervalForRemainingScheduledRetries" value="60" datatype="integer"/>
<parm name="PollOnLogin" value="true" datatype="boolean"/>
</characteristic>
</characteristic></characteristic></characteristic>
</wap-provisioningdoc>`,
		caThumb, base64.StdEncoding.EncodeToString(s.CA.Cert.Raw),
		thumb, base64.StdEncoding.EncodeToString(certDER),
		ProviderID, x(s.OrgName+" (Keystone MDM)"), x(s.PublicURL+PathManagement),
		x(deviceID), ProviderID, x(deviceID), x(name))
}

func soapFault(relatesTo, code, reason string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstepfault</a:Action><a:RelatesTo>%s</a:RelatesTo></s:Header>
<s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>%s</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en-US">%s</s:Text></s:Reason></s:Fault></s:Body>
</s:Envelope>`, x(relatesTo), x(code), x(reason))
}

func x(s string) string { return html.EscapeString(s) }
