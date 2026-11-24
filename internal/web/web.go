// Package web serves the admin dashboard.
package web

import (
	"crypto/subtle"
	"embed"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/TechTimCA/keystone-mdm/internal/store"
	"github.com/TechTimCA/keystone-mdm/internal/wmdm"
)

//go:embed templates/*.html
var files embed.FS

// UI is the admin dashboard.
type UI struct {
	Store     *store.Store
	PublicURL string
	OrgName   string
	AdminUser string
	AdminPass string
	tmpl      *template.Template
}

// Register mounts the dashboard on mux behind HTTP basic auth.
func (u *UI) Register(mux *http.ServeMux) {
	u.tmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"ago":   ago,
		"label": propLabel,
	}).ParseFS(files, "templates/*.html"))
	mux.Handle("GET /{$}", u.auth(u.devices))
	mux.Handle("GET /devices/{id}", u.auth(u.device))
	mux.Handle("POST /devices/{id}/actions/{key}", u.auth(u.action))
	mux.Handle("POST /devices/{id}/remove", u.auth(u.remove))
	mux.Handle("GET /enroll", u.auth(u.enroll))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
}

func (u *UI) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(u.AdminUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(u.AdminPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Keystone MDM"`)
			http.Error(w, "Sign in required", http.StatusUnauthorized)
			return
		}
		// Block cross-site form posts (CSRF): browsers send Origin on POST.
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" && hostOf(o) != hostOnly(r.Host) {
				http.Error(w, "cross-site request blocked", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		h(w, r)
	})
}

type deviceRow struct {
	store.Device
	Checks  []wmdm.Check
	Healthy bool
	Issues  int
}

func row(d store.Device) deviceRow {
	r := deviceRow{Device: d, Checks: wmdm.Health(d), Healthy: true}
	for _, c := range r.Checks {
		if c.State == "bad" {
			r.Issues++
			r.Healthy = false
		}
	}
	return r
}

func (u *UI) render(w http.ResponseWriter, name string, data map[string]any) {
	data["Org"] = u.OrgName
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := u.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("web: render %s: %v", name, err)
	}
}

func (u *UI) devices(w http.ResponseWriter, r *http.Request) {
	var rows []deviceRow
	attention, offline := 0, 0
	for _, d := range u.Store.Devices() {
		rr := row(d)
		if !rr.Healthy {
			attention++
		}
		if time.Since(d.LastSeen) > 24*time.Hour {
			offline++
		}
		rows = append(rows, rr)
	}
	u.render(w, "devices.html", map[string]any{
		"Title": "Devices", "Rows": rows, "Total": len(rows),
		"Attention": attention, "Offline": offline,
	})
}

func (u *UI) device(w http.ResponseWriter, r *http.Request) {
	d, ok := u.Store.Device(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	type prop struct{ Label, Value string }
	var props []prop
	for _, it := range wmdm.Inventory {
		if v, ok := d.Props[it.URI]; ok {
			props = append(props, prop{it.Label, v})
		}
	}
	u.render(w, "device.html", map[string]any{
		"Title": d.Name, "D": row(d), "Props": props,
		"Actions": wmdm.Actions, "Commands": u.Store.CommandsFor(d.ID, 30),
		"Flash": r.URL.Query().Get("sent"),
	})
}

func (u *UI) action(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := u.Store.Device(id); !ok {
		http.NotFound(w, r)
		return
	}
	a, cmds, ok := wmdm.ActionByKey(r.PathValue("key"), id)
	if !ok {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err := u.Store.Enqueue(cmds...); err != nil {
		http.Error(w, "could not queue: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/devices/"+url.PathEscape(id)+"?sent="+url.QueryEscape(a.Label), http.StatusSeeOther)
}

func (u *UI) remove(w http.ResponseWriter, r *http.Request) {
	if err := u.Store.DeleteDevice(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (u *UI) enroll(w http.ResponseWriter, r *http.Request) {
	link := "ms-device-enrollment:?mode=mdm&username=" + url.QueryEscape("you@"+hostOf(u.PublicURL)) +
		"&servername=" + url.QueryEscape(u.PublicURL+"/EnrollmentServer/Discovery.svc")
	u.render(w, "enroll.html", map[string]any{
		"Title": "Enroll a PC", "PublicURL": u.PublicURL,
		"Link": template.URL(link),
	})
}

func hostOf(raw string) string {
	p, err := url.Parse(raw)
	if err != nil {
		return "example.com"
	}
	return p.Hostname()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d.Minutes()), "min") + " ago"
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	default:
		return plural(int(d.Hours()/24), "day") + " ago"
	}
}

func plural(n int, unit string) string {
	s := itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func propLabel(uri string) string {
	for _, it := range wmdm.Inventory {
		if it.URI == uri {
			return it.Label
		}
	}
	return uri
}
