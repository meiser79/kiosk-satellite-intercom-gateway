package tests

import (
	"strings"
	"testing"

	"ks-intercom-gateway/src/gateway"
)

func TestCallerLabel(t *testing.T) {
	cases := []struct{ from, pai, want string }{
		{`"Anna Muster" <sip:0301234@pbx>;tag=a`, "", "Anna Muster (0301234)"},
		{`<sip:100@pbx>;tag=a`, "", "100"},
		{`Anna <sip:100@pbx>;tag=a`, "", "Anna (100)"},
		{`"100" <sip:100@pbx>;tag=a`, "", "100"},
		{`sip:100@pbx;tag=a`, "", "100"},
		{`"Bob" <sip:%2B4930123@pbx>;tag=a`, "", "Bob (+4930123)"},
		{`"Bob" <sip:1@pbx>;tag=a`, `"Real Company" <sip:0301234567@trunk>`, "Real Company (0301234567)"},
		{`"Zoë \"Z\"" <sip:7@pbx>;tag=a`, "", `Zoë "Z" (7)`},
		{"\"A\x00\x07B\" <sip:1@pbx>", "", "AB (1)"},
		{`<sip:anonymous@anonymous.invalid>;tag=a`, "", "anonymous"},
	}
	for _, c := range cases {
		if got := gateway.CallerLabel(c.from, c.pai); got != c.want {
			t.Errorf("CallerLabel(%q, %q) = %q, want %q", c.from, c.pai, got, c.want)
		}
	}
	long := `"` + strings.Repeat("x", 60) + `" <sip:1@h>;tag=a`
	if got := gateway.CallerLabel(long, ""); len([]rune(got)) != 40 || !strings.HasSuffix(got, "…") {
		t.Errorf("long name not cut to 40 runes: %q", got)
	}
}
