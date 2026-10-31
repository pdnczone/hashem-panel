package main

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestCommunityAllFeaturesIncluded(t *testing.T) {
    features := []string{"bagher","frp_ssh","cluster","sentinel","backhaul","xray","spoof","limits","watchdog","benchmark","diagnostics","performance","pathtest"}
    for _, f := range features {
        if !HasFeature(f) || !hasPro(f) { t.Errorf("%s not included",f) }
        w := httptest.NewRecorder()
        if proRequired(w,httptest.NewRequest("POST","/api/test",nil),f,f) { t.Errorf("%s still gated",f) }
    }
    w := httptest.NewRecorder()
    handleLicenseGet(w,httptest.NewRequest("GET","/api/license",nil))
    if w.Code!=http.StatusOK || !strings.Contains(w.Body.String(),`"edition":"community"`) { t.Fatalf("community status missing: %v %s",w.Code,w.Body.String()) }
    if cliLicense([]string{"check","cluster"})!=0 { t.Fatal("legacy CLI check should permit Community access") }
}
