package wmdm

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TechTimCA/keystone-mdm/internal/store"
)

// Incoming SyncML (OMA-DM 1.2) message from a Windows PC.
type syncML struct {
	Hdr struct {
		SessionID string `xml:"SessionID"`
		MsgID     string `xml:"MsgID"`
		Source    struct {
			LocURI string `xml:"LocURI"`
		} `xml:"Source"`
	} `xml:"SyncHdr"`
	Body struct {
		Alerts   []dmCmd    `xml:"Alert"`
		Replaces []dmCmd    `xml:"Replace"`
		Results  []dmCmd    `xml:"Results"`
		Statuses []dmStatus `xml:"Status"`
	} `xml:"SyncBody"`
}

type dmCmd struct {
	CmdID string `xml:"CmdID"`
	Data  string `xml:"Data"`
	Items []struct {
		Source struct {
			LocURI string `xml:"LocURI"`
		} `xml:"Source"`
		Data string `xml:"Data"`
	} `xml:"Item"`
}

type dmStatus struct {
	CmdRef string `xml:"CmdRef"`
	Cmd    string `xml:"Cmd"`
	Data   string `xml:"Data"`
}

// cmdIDPrefix marks CmdIDs that refer to queued Keystone commands.
const cmdIDPrefix = "ks-"

// maxPerMessage keeps responses small; the session continues until the queue is empty.
const maxPerMessage = 25

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var in syncML
	if err := xml.Unmarshal(b, &in); err != nil {
		http.Error(w, "bad syncml", http.StatusBadRequest)
		return
	}
	deviceID := in.Hdr.Source.LocURI
	dev, ok := s.Store.Device(deviceID)
	if !ok {
		log.Printf("wmdm: check-in from unknown device %q", deviceID)
		http.Error(w, "unknown device", http.StatusForbidden)
		return
	}
	if !s.clientCertOK(r, deviceID) {
		log.Printf("wmdm: client certificate mismatch for %q", deviceID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Record what the device told us.
	props := map[string]string{}
	for _, group := range [][]dmCmd{in.Body.Replaces, in.Body.Results} {
		for _, c := range group {
			for _, it := range c.Items {
				if it.Source.LocURI != "" {
					props[it.Source.LocURI] = strings.TrimSpace(it.Data)
				}
			}
		}
	}
	for _, st := range in.Body.Statuses {
		if strings.HasPrefix(st.CmdRef, cmdIDPrefix) {
			if err := s.Store.Complete(strings.TrimPrefix(st.CmdRef, cmdIDPrefix), st.Data); err != nil {
				log.Printf("wmdm: complete: %v", err)
			}
		}
	}
	_ = s.Store.UpsertDevice(deviceID, func(d *store.Device) {
		d.LastSeen = time.Now().UTC()
		for k, v := range props {
			d.Props[k] = v
		}
		applyKnownProps(d)
	})

	// Refresh inventory once a day.
	if inv := dev.Props["_inventoryAt"]; inv == "" || stale(inv, 24*time.Hour) {
		_ = s.Store.UpsertDevice(deviceID, func(d *store.Device) {
			d.Props["_inventoryAt"] = time.Now().UTC().Format(time.RFC3339)
		})
		_ = s.Store.Enqueue(InventoryCommands(deviceID)...)
	}

	// Build the reply: a Status for the header and for every device command,
	// then any queued commands, then Final.
	var out strings.Builder
	n := 0
	next := func() int { n++; return n }
	status := func(cmdRef, cmd, code string) {
		fmt.Fprintf(&out, "<Status><CmdID>%d</CmdID><MsgRef>%s</MsgRef><CmdRef>%s</CmdRef><Cmd>%s</Cmd><Data>%s</Data></Status>\n",
			next(), x(in.Hdr.MsgID), x(cmdRef), cmd, code)
	}
	status("0", "SyncHdr", "200")
	for _, c := range in.Body.Alerts {
		status(c.CmdID, "Alert", "200")
	}
	for _, c := range in.Body.Replaces {
		status(c.CmdID, "Replace", "200")
	}
	for _, c := range in.Body.Results {
		status(c.CmdID, "Results", "200")
	}
	queued, err := s.Store.TakeQueued(deviceID, maxPerMessage)
	if err != nil {
		log.Printf("wmdm: take queued: %v", err)
	}
	for _, c := range queued {
		out.WriteString(renderCommand(c))
	}

	w.Header().Set("Content-Type", "application/vnd.syncml.dm+xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
<SyncHdr>
<VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto>
<SessionID>%s</SessionID><MsgID>%s</MsgID>
<Target><LocURI>%s</LocURI></Target>
<Source><LocURI>%s</LocURI></Source>
</SyncHdr>
<SyncBody>
%s<Final/>
</SyncBody>
</SyncML>`, x(in.Hdr.SessionID), x(in.Hdr.MsgID), x(deviceID), x(s.PublicURL+PathManagement), out.String())
}

func renderCommand(c store.Command) string {
	meta := ""
	if c.Format != "" {
		meta = fmt.Sprintf(`<Meta><Format xmlns="syncml:metinf">%s</Format></Meta>`, x(c.Format))
	}
	data := ""
	if c.Data != "" {
		data = "<Data>" + x(c.Data) + "</Data>"
	}
	return fmt.Sprintf("<%s><CmdID>%s%s</CmdID><Item><Target><LocURI>%s</LocURI></Target>%s%s</Item></%s>\n",
		c.Verb, cmdIDPrefix, x(c.ID), x(c.LocURI), meta, data, c.Verb)
}

// clientCertOK checks the TLS client certificate when Keystone terminates TLS itself.
// Behind a reverse proxy the certificate is not visible; see README "Security notes".
func (s *Server) clientCertOK(r *http.Request, deviceID string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return s.TrustProxyTLS
	}
	c := r.TLS.PeerCertificates[0]
	if err := c.CheckSignatureFrom(s.CA.Cert); err != nil {
		return false
	}
	return c.Subject.CommonName == deviceID
}

func stale(ts string, age time.Duration) bool {
	t, err := time.Parse(time.RFC3339, ts)
	return err != nil || time.Since(t) > age
}

// applyKnownProps copies well-known OMA-URI values onto device fields.
func applyKnownProps(d *store.Device) {
	set := func(dst *string, uri string) {
		if v := d.Props[uri]; v != "" {
			*dst = v
		}
	}
	set(&d.Name, "./DevDetail/Ext/Microsoft/DeviceName")
	set(&d.Manufacturer, "./DevInfo/Man")
	set(&d.Model, "./DevInfo/Mod")
	set(&d.OSVersion, "./DevDetail/SwV")
}
