package main

import (
	"encoding/csv"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// P5: reminders, history, templates, bulk renew, CSV.

func custHistKinds(c customer) string {
	var k []string
	for _, h := range c.History {
		k = append(k, h.Kind)
	}
	return strings.Join(k, ",")
}

func TestCustomersReminders(t *testing.T) {
	l := newCustLab(t)
	withPro(t)
	if code, m := custPost(t, custCreateBody); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	setEnd := func(d time.Duration) {
		custs.Lock()
		custFindLocked(1).ExpiresAt = time.Now().Add(d).Unix()
		custs.Unlock()
	}
	alerts := func() []custEvent {
		l.mu.Lock()
		defer l.mu.Unlock()
		var out []custEvent
		for _, a := range l.alerts {
			if a.to == "days left" {
				out = append(out, a)
			}
		}
		return out
	}
	customersTick(time.Now())
	if n := len(alerts()); n != 0 {
		t.Fatalf("a reminder 30 days before the end: %d", n)
	}
	// 2.5 days left: the 3-day reminder, once
	setEnd(60 * time.Hour)
	customersTick(time.Now())
	customersTick(time.Now())
	if a := alerts(); len(a) != 1 || !strings.Contains(a[0].why, "3 day(s) left") {
		t.Fatalf("3-day reminder: %+v", a)
	}
	// 20 hours left: the 1-day reminder, once
	setEnd(20 * time.Hour)
	customersTick(time.Now())
	customersTick(time.Now())
	if a := alerts(); len(a) != 2 || !strings.Contains(a[1].why, "1 day(s) left") {
		t.Fatalf("1-day reminder: %+v", a)
	}
	// a renewal starts a new period: the reminders come again before its end
	if code, m := custPost(t, `{"action":"renew","id":1,"days":2,"reset_usage":false}`); code != 200 {
		t.Fatalf("renew: %d %v", code, m)
	}
	if c := custGet(t, 1); len(c.Periods) != 0 {
		t.Errorf("renew without reset kept a period: %v", c.Periods)
	}
	customersTick(time.Now()) // 2 days 20 hours left: the 3-day one (the renewal's tick sent it)
	if a := alerts(); len(a) != 3 || !strings.Contains(a[2].why, "3 day(s) left") {
		t.Errorf("after renew: %+v", a)
	}
	// starting with less than a day: one reminder (1 day), not two
	setEnd(5 * time.Hour)
	custs.Lock()
	custFindLocked(1).Reminded = 0
	custs.Unlock()
	customersTick(time.Now())
	if a := alerts(); len(a) != 4 || !strings.Contains(a[3].why, "1 day(s) left") {
		t.Errorf("a plan with hours left: %+v", a)
	}
	// renewed by a day (29 hours left: the 3-day reminder again), then cut:
	// a cut customer gets no reminder
	if code, _ := custPost(t, `{"action":"renew","id":1,"days":1}`); code != 200 {
		t.Fatal("renew")
	}
	custPost(t, `{"action":"cut","id":1}`)
	setEnd(5 * time.Hour)
	customersTick(time.Now())
	if a := alerts(); len(a) != 5 {
		t.Errorf("a cut customer was reminded: %+v", a)
	}
	if k := custHistKinds(custGet(t, 1)); k != "created,reminder,reminder,renew,reminder,reminder,renew,reminder,cut" {
		t.Errorf("history: %s", k)
	}
}

func TestCustomersHistory(t *testing.T) {
	newCustLab(t)
	withPro(t)
	if code, m := custPost(t, custCreateBody); code != 200 {
		t.Fatalf("create: %d %v", code, m)
	}
	custs.Lock()
	c := custFindLocked(1)
	c.UsedRx, c.UsedTx = 3e9, 1e9
	custs.Unlock()
	steps := []string{
		`{"action":"update","id":1,"name":"Ali","quota_gb":20,"rate_mbit":20}`,
		`{"action":"update","id":1,"name":"Ali B","quota_gb":20,"rate_mbit":20}`, // no plan change: no entry
		`{"action":"reset","id":1}`,
		`{"action":"cut","id":1}`,
		`{"action":"resume","id":1}`,
		`{"action":"link-add","id":1,"link":{"name":"x","ports":"9443"}}`,
		`{"action":"link-remove","id":1,"link_id":3}`,
		`{"action":"renew","id":1,"days":10}`,
	}
	for _, s := range steps {
		if code, m := custPost(t, s); code != 200 {
			t.Fatalf("%s: %d %v", s, code, m)
		}
	}
	c2 := custGet(t, 1)
	if k := custHistKinds(c2); k != "created,plan,reset,cut,resume,link,link,renew" {
		t.Errorf("history: %s", k)
	}
	if !strings.Contains(c2.History[2].Text, "4.00 GB") || !strings.Contains(c2.History[1].Text, "volume 20 GB") {
		t.Errorf("history text: %+v", c2.History)
	}
	// the reset kept the period it ended; the renewal (usage reset) one more
	if len(c2.Periods) != 2 || c2.Periods[0].Used != 4e9 || c2.Periods[0].QuotaGB != 20 {
		t.Errorf("periods: %+v", c2.Periods)
	}
	// the caps
	for i := 0; i < custHistMax+20; i++ {
		c2.logEvent(time.Now(), "plan", fmt.Sprint(i))
	}
	for i := 0; i < custPeriodMax+5; i++ {
		c2.endPeriod(time.Now())
	}
	if len(c2.History) != custHistMax || c2.History[custHistMax-1].Text != fmt.Sprint(custHistMax+19) || len(c2.Periods) != custPeriodMax {
		t.Errorf("caps: %d entries (last %q), %d periods", len(c2.History), c2.History[len(c2.History)-1].Text, len(c2.Periods))
	}
	// the status page shows none of it
	tok := c2.Token
	if _, ok := any(custPublicView(c2, [2]float64{}, time.Now())).(custPublic); !ok || strings.Contains(fmt.Sprintf("%+v", custPublicView(c2, [2]float64{}, time.Now())), "renewed") {
		t.Error("the status page carries the history")
	}
	_ = tok
}

func TestCustomersTemplatesAndBulk(t *testing.T) {
	newCustLab(t)
	withPro(t)
	for _, s := range []string{custCreateBody,
		`{"action":"create","name":"Reza","days":30,"links":[{"name":"a","ports":"9443"}]}`} {
		if code, m := custPost(t, s); code != 200 {
			t.Fatalf("create: %d %v", code, m)
		}
	}
	// templates: add, a duplicate name refused, change, remove
	for _, s := range []string{
		`{"action":"template-save","name":"Gold","days":30,"quota_gb":100,"rate_mbit":50}`,
		`{"action":"template-save","name":"Silver","days":30,"quota_gb":50}`,
	} {
		if code, m := custPost(t, s); code != 200 {
			t.Fatalf("%s: %d %v", s, code, m)
		}
	}
	for _, s := range []string{
		`{"action":"template-save","name":"gold","days":30}`,
		`{"action":"template-save","name":"","days":30}`,
		`{"action":"template-save","name":"X","days":0}`,
		`{"action":"template-save","template_id":9,"name":"X","days":3}`,
		`{"action":"template-remove","template_id":9}`,
	} {
		if code, _ := custPost(t, s); code == 200 {
			t.Errorf("accepted %s", s)
		}
	}
	custPost(t, `{"action":"template-save","template_id":2,"name":"Silver","days":60,"quota_gb":50}`)
	custPost(t, `{"action":"template-remove","template_id":1}`)
	custs.Lock()
	tpl := append([]custTemplate(nil), custs.f.Templates...)
	custs.Unlock()
	if len(tpl) != 1 || tpl[0].ID != 2 || tpl[0].Days != 60 {
		t.Errorf("templates: %+v", tpl)
	}
	if v := customersView(); fmt.Sprint(v["templates"]) == "<nil>" {
		t.Error("the view has no templates")
	}

	// bulk renew: all or none
	e1, e2 := custGet(t, 1).ExpiresAt, custGet(t, 2).ExpiresAt
	if code, _ := custPost(t, `{"action":"bulk-renew","ids":[1,99],"days":10}`); code == 200 {
		t.Fatal("a bulk renew with an unknown customer was accepted")
	}
	if custGet(t, 1).ExpiresAt != e1 || len(custGet(t, 1).History) != 1 {
		t.Fatal("a failed bulk renew changed a customer")
	}
	if code, _ := custPost(t, `{"action":"bulk-renew","ids":[],"days":10}`); code == 200 {
		t.Error("an empty bulk renew was accepted")
	}
	if code, m := custPost(t, `{"action":"bulk-renew","ids":[1,2,2],"days":10,"reset_usage":false}`); code != 200 {
		t.Fatalf("bulk renew: %d %v", code, m)
	}
	if d := custGet(t, 1).ExpiresAt - e1; d != 10*86400 || custGet(t, 2).ExpiresAt-e2 != 10*86400 {
		t.Errorf("bulk renew: +%d s", d)
	}
}

func TestCustomersNewActionsNeedPro(t *testing.T) {
	newCustLab(t)
	setTestLicense(t, nil)
	for _, s := range []string{
		`{"action":"template-save","name":"Gold","days":30}`,
		`{"action":"template-remove","template_id":1}`,
		`{"action":"bulk-renew","ids":[1],"days":10}`,
	} {
		if code, m := custPost(t, s); code != 403 || m["error_code"] != "E-LIC-01" {
			t.Errorf("%s without a license: %d %v", s, code, m)
		}
	}
}

func TestCustomersExportCSV(t *testing.T) {
	newCustLab(t)
	withPro(t)
	for _, s := range []string{custCreateBody,
		`{"action":"create","name":"=HYPERLINK(\"x\")","note":"+1 @x","days":0,"links":[{"name":"a","ports":"9443"}]}`} {
		if code, m := custPost(t, s); code != 200 {
			t.Fatalf("create: %d %v", code, m)
		}
	}
	rr := httptest.NewRecorder()
	handleCustomersExport(rr, httptest.NewRequest("GET", "/api/customers/export.csv", nil))
	body := rr.Body.String()
	if !strings.HasPrefix(body, "\xef\xbb\xbf") || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export: %q %v", body[:min(20, len(body))], rr.Header())
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(body, "\xef\xbb\xbf"))).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows: %v %d\n%s", err, len(rows), body)
	}
	if rows[0][1] != "name" || rows[1][1] != "Ali" || rows[1][12] != "443 2083 8443" || rows[1][9] != "0.000" || rows[1][8] != "10" {
		t.Errorf("row 1: %v", rows[1])
	}
	if rows[2][1] != `'=HYPERLINK("x")` || rows[2][2] != "'+1 @x" || rows[2][5] != "" {
		t.Errorf("formula cells not neutralised: %v", rows[2])
	}
}
