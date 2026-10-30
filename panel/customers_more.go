package main

// P5: reminders, history, plan templates, bulk renew and the CSV export
// of the sold tunnels (customers.go is the rest).

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	custHistMax     = 100 // history entries kept per customer
	custPeriodMax   = 24  // ended periods kept per customer
	custTemplateMax = 50
	custBulkMax     = 500
)

// custReminderDays: the reminders before a plan ends, each once a period.
var custReminderDays = []int{3, 1}

// custHist is one entry of a customer's history.
type custHist struct {
	At   int64  `json:"at"`
	Kind string `json:"kind"` // created | plan | renew | cut | resume | reset | reminder | link
	Text string `json:"text"`
}

// custPeriod is a usage period that ended (a renewal or a reset that
// cleared the usage).
type custPeriod struct {
	Start   int64   `json:"start"`
	End     int64   `json:"end"`
	Used    uint64  `json:"used"`
	QuotaGB float64 `json:"quota_gb,omitempty"`
}

// custTemplate is a saved plan.
type custTemplate struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Days     int     `json:"days"`
	QuotaGB  float64 `json:"quota_gb"`
	RateMbit float64 `json:"rate_mbit"`
}

// logEvent adds an entry to c's history (the oldest go past custHistMax).
func (c *customer) logEvent(now time.Time, kind, text string) {
	c.History = append(c.History, custHist{At: now.Unix(), Kind: kind, Text: text})
	if n := len(c.History) - custHistMax; n > 0 {
		c.History = append([]custHist(nil), c.History[n:]...)
	}
}

// endPeriod keeps the period that ends now (its usage is about to be
// cleared).
func (c *customer) endPeriod(now time.Time) {
	start := c.PeriodStart
	if start == 0 {
		start = c.Created
	}
	c.Periods = append(c.Periods, custPeriod{Start: start, End: now.Unix(), Used: c.used(), QuotaGB: c.QuotaGB})
	if n := len(c.Periods) - custPeriodMax; n > 0 {
		c.Periods = append([]custPeriod(nil), c.Periods[n:]...)
	}
}

// custPlanText describes a plan for the history.
func custPlanText(days int, quotaGB, rateMbit float64) string {
	part := func(v float64, unit string) string {
		if v <= 0 {
			return "unlimited"
		}
		return strconv.FormatFloat(v, 'f', -1, 64) + " " + unit
	}
	d := "no end date"
	if days > 0 {
		d = strconv.Itoa(days) + " days"
	}
	return d + ", volume " + part(quotaGB, "GB") + ", speed " + part(rateMbit, "Mbit/s")
}

// custRemind: the reminder c is due now (days left, 0: none) and marks it
// sent. One per threshold and period; a renewal starts a new period.
func (c *customer) custRemind(now time.Time) int {
	if c.Cut != "" || c.ExpiresAt <= 0 || now.Unix() >= c.ExpiresAt {
		return 0
	}
	left := c.ExpiresAt - now.Unix()
	due := 0
	for _, d := range custReminderDays {
		if left <= int64(d)*86400 && (c.Reminded == 0 || c.Reminded > d) {
			due = d // the smallest threshold passed: one alert, not two
		}
	}
	if due == 0 {
		return 0
	}
	c.Reminded = due
	days := int((left + 86399) / 86400)
	return days
}

// startReminders marks as sent the reminders a new period already starts
// inside (a 2-day plan gets no "3 days left" the moment it is sold).
func (c *customer) startReminders(now time.Time) {
	c.Reminded = 0
	if c.ExpiresAt <= 0 {
		return
	}
	left := c.ExpiresAt - now.Unix()
	for _, d := range custReminderDays {
		if left <= int64(d)*86400 && (c.Reminded == 0 || c.Reminded > d) {
			c.Reminded = d
		}
	}
}

// custRenewLocked renews c by days from its end (or now, when it ended),
// as the renew action does; reset clears the usage into a new period.
func custRenewLocked(c *customer, days int, reset bool, now time.Time) error {
	if days == 0 {
		days = c.Days
	}
	if days < 1 || days > 3660 {
		return fmt.Errorf("days: 1 to 3660")
	}
	from := now
	if c.ExpiresAt > now.Unix() {
		from = time.Unix(c.ExpiresAt, 0)
	}
	c.ExpiresAt = from.Add(time.Duration(days) * 24 * time.Hour).Unix()
	c.Days = days
	c.startReminders(now)
	text := fmt.Sprintf("renewed for %d days, until %s", days, time.Unix(c.ExpiresAt, 0).UTC().Format("2006-01-02"))
	if reset {
		c.endPeriod(now)
		c.UsedRx, c.UsedTx, c.Warned, c.PeriodStart = 0, 0, false, now.Unix()
		text += "; usage reset"
	}
	if c.Cut == "expired" || (c.Cut == "quota" && (c.quotaBytes() == 0 || c.used() < c.quotaBytes())) {
		c.Cut = ""
		text += "; reconnected"
	}
	c.logEvent(now, "renew", text)
	return nil
}

// custTemplateSaveLocked adds (ID 0) or changes a template.
func custTemplateSaveLocked(req custRequest) (int, error) {
	name, err := custCleanText(req.Name, 40)
	if err != nil || name == "" {
		return 0, fmt.Errorf("template name: 1 to 40 characters")
	}
	if req.Days < 1 {
		return 0, fmt.Errorf("days: 1 to 3660")
	}
	if err := custValidatePlan(req.QuotaGB, req.RateMbit, req.Days); err != nil {
		return 0, err
	}
	t := custTemplate{ID: req.TemplateID, Name: name, Days: req.Days, QuotaGB: req.QuotaGB, RateMbit: req.RateMbit}
	for _, x := range custs.f.Templates {
		if strings.EqualFold(x.Name, name) && x.ID != t.ID {
			return 0, fmt.Errorf("a template is already named %q", name)
		}
	}
	if t.ID != 0 {
		for i := range custs.f.Templates {
			if custs.f.Templates[i].ID == t.ID {
				custs.f.Templates[i] = t
				return t.ID, nil
			}
		}
		return 0, fmt.Errorf("no template %d", t.ID)
	}
	if len(custs.f.Templates) >= custTemplateMax {
		return 0, fmt.Errorf("at most %d templates", custTemplateMax)
	}
	for _, x := range custs.f.Templates {
		if x.ID >= t.ID {
			t.ID = x.ID + 1
		}
	}
	if t.ID == 0 {
		t.ID = 1
	}
	custs.f.Templates = append(custs.f.Templates, t)
	return t.ID, nil
}

func custTemplateRemoveLocked(id int) error {
	for i, t := range custs.f.Templates {
		if t.ID == id {
			custs.f.Templates = append(custs.f.Templates[:i], custs.f.Templates[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no template %d", id)
}

// custBulkRenewLocked renews every customer of ids, or none (an error
// leaves them all as they were: the caller restores its snapshot).
func custBulkRenewLocked(ids []int, days int, reset bool, now time.Time) error {
	if len(ids) == 0 {
		return fmt.Errorf("choose at least one customer")
	}
	if len(ids) > custBulkMax {
		return fmt.Errorf("at most %d customers at once", custBulkMax)
	}
	seen := map[int]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		c := custFindLocked(id)
		if c == nil {
			return fmt.Errorf("no customer %d", id)
		}
		if err := custRenewLocked(c, days, reset, now); err != nil {
			return fmt.Errorf("%s: %v", c.Name, err)
		}
	}
	return nil
}

// custLinkText is a link in a few words, for the history.
func custLinkText(l customerLink) string {
	ports := make([]string, len(l.Ports))
	for i, p := range l.Ports {
		ports[i] = strconv.Itoa(p)
	}
	t := l.Engine + " " + l.Transport + ", ports " + strings.Join(ports, ",")
	if l.GRE {
		t += ", GRE"
	}
	return t
}

// custCSVCell keeps a spreadsheet from reading a cell as a formula.
func custCSVCell(s string) string {
	if r := []rune(s); len(r) > 0 && strings.ContainsRune("=+-@;\t\r＝＋－＠", r[0]) {
		return "'" + s
	}
	return s
}

// custStatusWord is a customer's state for the export.
func custStatusWord(c customer) string {
	if c.Cut != "" {
		return "cut (" + c.Cut + ")"
	}
	return "active"
}

// handleCustomersExport: every customer as CSV (one row each).
func handleCustomersExport(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	custs.Lock()
	custLoadLocked()
	list, loadErr := cloneCustomersFile(custs.f).Customers, custs.loadErr
	custs.Unlock()
	if loadErr != "" {
		writeAPIError(w, r, "E-CUST-06", "customers.json cannot be read: "+loadErr)
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="customers-%s.csv"`, now.UTC().Format("20060102")))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("\xef\xbb\xbf")) // UTF-8 BOM: Excel reads Persian names right
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "name", "note", "status", "created_utc", "expires_utc", "days_left", "plan_days",
		"volume_gb", "used_gb", "speed_mbit", "foreign_servers", "ports"})
	date := func(t int64) string {
		if t <= 0 {
			return ""
		}
		return time.Unix(t, 0).UTC().Format("2006-01-02 15:04")
	}
	num := func(v float64) string {
		if v <= 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	for _, c := range list {
		left := ""
		if d := daysLeft(c.ExpiresAt, now); d != nil {
			left = strconv.Itoa(*d)
		}
		var ports []string
		for _, l := range c.Links {
			for _, p := range l.Ports {
				ports = append(ports, strconv.Itoa(p))
			}
		}
		row := []string{strconv.Itoa(c.ID), c.Name, c.Note, custStatusWord(c), date(c.Created), date(c.ExpiresAt), left,
			strconv.Itoa(c.Days), num(c.QuotaGB), strconv.FormatFloat(float64(c.used())/gb, 'f', 3, 64), num(c.RateMbit),
			strconv.Itoa(len(c.Links)), strings.Join(ports, " ")}
		for i := range row {
			row[i] = custCSVCell(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

// handleCustomersHistory: one customer's history and ended periods (kept
// out of the list the page polls).
func handleCustomersHistory(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	custs.Lock()
	custLoadLocked()
	var hist []custHist
	var per []custPeriod
	found := false
	if c := custFindLocked(id); c != nil {
		hist, per, found = append([]custHist{}, c.History...), append([]custPeriod{}, c.Periods...), true
	}
	custs.Unlock()
	if !found {
		writeAPIError(w, r, "E-CUST-04", fmt.Sprintf("no customer %d", id))
		return
	}
	writeJSON(w, map[string]any{"id": id, "history": hist, "periods": per})
}
