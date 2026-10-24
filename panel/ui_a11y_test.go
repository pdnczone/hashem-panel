package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func readUI(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Nothing in the panel renders below the 12px project minimum.
func TestUINoTextBelow12px(t *testing.T) {
	small := regexp.MustCompile(`font(?:-size)?\s*:(?:[^;"'{}]*?\s)?(?:[0-9]|1[01])(?:\.\d+)?px`)
	for _, f := range []string{"index.html", "app.js", "tokens.css", "base.css", "enterprise.css"} {
		if m := small.FindAllString(readUI(t, f), 5); len(m) > 0 {
			t.Errorf("%s: font sizes below 12px: %v", f, m)
		}
	}
}

// White text sits on --ac-fill, which the default blue darkens to 5.5:1; a raw
// var(--ac) fill under --ac-on is 3.6:1.
func TestUIAccentFillUnderOnText(t *testing.T) {
	if !strings.Contains(readUI(t, "tokens.css"), "--ac-fill:") {
		t.Fatal("tokens.css must define --ac-fill")
	}
	raw := regexp.MustCompile(`background\s*:\s*var\(--ac\)\s*;\s*color\s*:\s*var\(--ac-on\)`)
	for _, f := range []string{"index.html", "tokens.css", "base.css", "enterprise.css"} {
		if raw.MatchString(readUI(t, f)) {
			t.Errorf("%s: --ac-on text on a raw var(--ac) fill; use var(--ac-fill)", f)
		}
	}
}

// Every text field in the static markup has an accessible name.
func TestUIFieldsHaveLabels(t *testing.T) {
	html := readUI(t, "index.html")
	fors := map[string]bool{}
	for _, m := range regexp.MustCompile(`<label[^>]*\bfor="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		fors[m[1]] = true
	}
	field := regexp.MustCompile(`<(?:input|select|textarea)\b[^>]*>`)
	id := regexp.MustCompile(`\bid="([^"]+)"`)
	skip := regexp.MustCompile(`type="(?:hidden|checkbox|radio|button|submit|file)"`)
	// Fields wrapped in a <label> are named by it; strip those first.
	unwrapped := regexp.MustCompile(`(?s)<label\b[^>]*>.*?</label>`).ReplaceAllString(html, "")
	for _, tag := range field.FindAllString(unwrapped, -1) {
		if skip.MatchString(tag) || strings.Contains(tag, "aria-label") || strings.Contains(tag, " title=") {
			continue
		}
		if m := id.FindStringSubmatch(tag); m != nil && fors[m[1]] {
			continue
		}
		t.Errorf("field without a label: %s", tag)
	}
}

// With no saved choice the theme follows the system appearance.
func TestUIThemeFollowsSystem(t *testing.T) {
	if !strings.Contains(readUI(t, "index.html"), "prefers-color-scheme: light") ||
		!strings.Contains(readUI(t, "app.js"), "prefers-color-scheme: light") {
		t.Error("theme bootstrap must consult prefers-color-scheme")
	}
}

// Colors assigned from JS (el.style.color = ...) follow the same rule.
func TestUINoHardcodedColorsInJSStyle(t *testing.T) {
	re := regexp.MustCompile(`\.style\.(?:color|background|backgroundColor|borderColor)\s*=\s*[^;\n]*#[0-9a-fA-F]{3,6}\b`)
	for _, m := range re.FindAllString(readUI(t, "app.js"), -1) {
		if !strings.HasSuffix(m, "#fff") { // white text on a status fill is allowed

			t.Errorf("hard-coded color from JS: %s", m)
		}
	}
}

// Colors come from tokens.css: hard-coded colors break the light theme and the
// accent presets. White text on a status fill is the only literal allowed.
func TestUINoHardcodedColors(t *testing.T) {
	decl := regexp.MustCompile(`(?:^|[^\w-])(color|background(?:-color)?|border(?:-[a-z]+)?|fill|stroke)\s*:\s*[^;"'{}<>` + "`" + `]*?(#[0-9a-fA-F]{3,6}\b|rgba?\([^)]*\))`)
	canvas := regexp.MustCompile(`fillStyle|strokeStyle|addColorStop|C_[A-Z]+ *=|xterm|selectionBackground`)
	for _, f := range []string{"index.html", "app.js", "enterprise.css", "base.css"} {
		for i, line := range strings.Split(readUI(t, f), "\n") {
			if canvas.MatchString(line) {
				continue
			}
			for _, m := range decl.FindAllStringSubmatch(line, -1) {
				if v := strings.ToLower(m[2]); m[1] == "color" && (v == "#fff" || v == "#ffffff") {
					continue
				}
				t.Errorf("%s:%d: hard-coded color %q", f, i+1, strings.TrimSpace(m[0]))
			}
		}
	}
}

// Icons come from the SVG sprite (#i-*), not emoji: emoji render differently on
// every OS, cannot follow the theme color and read as noise in labels.
// The typographic marks check and cross stay.
func TestUINoEmoji(t *testing.T) {
	emoji := regexp.MustCompile("[\U0001F300-\U0001FAFF☀-➿⭐⏩-⏺]")
	for _, f := range []string{"index.html", "app.js"} {
		for i, line := range strings.Split(readUI(t, f), "\n") {
			for _, m := range emoji.FindAllString(line, -1) {
				if m == "✓" || m == "✗" || m == "☰" { // check, cross, menu
					continue
				}
				t.Errorf("%s:%d: emoji %q in UI", f, i+1, m)
			}
		}
	}
}

// A var(--x) that nobody defines silently falls back to the property's initial
// value (square corners, transparent borders); every token used must exist.
func TestUICSSVarsDefined(t *testing.T) {
	files := []string{"index.html", "app.js", "tokens.css", "base.css", "enterprise.css", "fonts.css"}
	defined := map[string]bool{}
	def := regexp.MustCompile(`(--[\w-]+)\s*:|setProperty\('(--[\w-]+)'`)
	for _, f := range files {
		for _, m := range def.FindAllStringSubmatch(readUI(t, f), -1) {
			defined[m[1]+m[2]] = true
		}
	}
	use := regexp.MustCompile(`var\((--[\w-]+)\s*([,)])`)
	for _, f := range files {
		for _, m := range use.FindAllStringSubmatch(readUI(t, f), -1) {
			if m[2] == ")" && !defined[m[1]] && m[1] != "--token" { // --token: placeholder in a comment
				t.Errorf("%s: var(%s) is never defined", f, m[1])
			}
		}
	}
}

// Rem sizes count too: 0.75rem is the 12px floor.
func TestUINoRemTextBelow12px(t *testing.T) {
	small := regexp.MustCompile(`font-size\s*:\s*0?\.(?:[0-6]\d*|7[0-4]\d*)rem`)
	for _, f := range []string{"index.html", "app.js", "tokens.css", "base.css", "enterprise.css"} {
		if m := small.FindAllString(readUI(t, f), 5); len(m) > 0 {
			t.Errorf("%s: rem font sizes below 12px: %v", f, m)
		}
	}
}

// Styling lives in classes; inline style is only for values computed at runtime
// and a few one-off positions.
func TestUIInlineStyleBudget(t *testing.T) {
	n := 0
	for _, f := range []string{"index.html", "app.js"} {
		n += strings.Count(readUI(t, f), `style="`)
	}
	if n > 40 {
		t.Errorf("%d inline style attributes; move static styling to classes (budget 40)", n)
	}
}

// Modals open through modalShow/trapModal so Escape closes them, Tab stays
// inside and focus returns to the opener; flipping .hidden directly skips that.
func TestUIModalsAreTrapped(t *testing.T) {
	direct := regexp.MustCompile(`(?i)modal'?\)?\.hidden\s*=\s*false|\bm\.hidden\s*=\s*false`)
	if m := direct.FindAllString(readUI(t, "app.js"), -1); len(m) > 0 {
		t.Errorf("modal shown without modalShow/trapModal: %v", m)
	}
}

// A handler referenced but never defined throws at load and stops the rest of
// app.js from running (sshfwdClearDnatClick once took Sentinel and Cluster down).
func TestUIHandlersDefined(t *testing.T) {
	js, html := readUI(t, "app.js"), readUI(t, "index.html")
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)(?:function\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)`).FindAllStringSubmatch(js, -1) {
		defined[m[1]] = true
	}
	refs := map[string]string{}
	for _, m := range regexp.MustCompile(`on(?:click|change|input|submit)="\s*([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(html+js, -1) {
		refs[m[1]] = "inline handler"
	}
	for _, m := range regexp.MustCompile(`\bon\('[\w-]+',\s*'\w+',\s*([A-Za-z_$][\w$]*)\)`).FindAllStringSubmatch(js, -1) {
		refs[m[1]] = "on()"
	}
	for _, m := range regexp.MustCompile(`window\.([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*);`).FindAllStringSubmatch(js, -1) {
		if !strings.HasPrefix(m[1], "_") { // window._x = localVar stores state, not a handler
			refs[m[2]] = "window export"
		}
	}
	builtin := map[string]bool{"event": true, "this": true, "location": true, "history": true, "window": true, "document": true}
	for name, where := range refs {
		if !defined[name] && !builtin[name] {
			t.Errorf("%s %s is not defined in app.js", where, name)
		}
	}
}

// Stray control characters (a backspace where a regex \b was meant) break code silently.
func TestUINoControlChars(t *testing.T) {
	for _, f := range []string{"index.html", "app.js", "i18n-fa.js", "tokens.css", "base.css", "enterprise.css"} {
		for i, r := range readUI(t, f) {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' {
				t.Errorf("%s: control character %U at byte %d", f, r, i)
				break
			}
		}
	}
}
