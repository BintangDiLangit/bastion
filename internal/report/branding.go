package report

import (
	"fmt"
	"html/template"
	"regexp"
	"strconv"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func hexOK(s string) bool { return hexColor.MatchString(s) }

// darken multiplies each RGB channel by f (0..1). Used to derive the cover
// gradient's deep tone from the brand color without extra config.
func darken(hex string, f float64) string {
	if !hexOK(hex) {
		return hex
	}
	ch := func(s string) int {
		v, _ := strconv.ParseInt(s, 16, 0)
		n := int(float64(v) * f)
		if n < 0 {
			n = 0
		}
		if n > 255 {
			n = 255
		}
		return n
	}
	return fmt.Sprintf("#%02x%02x%02x", ch(hex[1:3]), ch(hex[3:5]), ch(hex[5:7]))
}

// brandCSS builds the CSS-variable override for a custom brand color, or "" for
// an invalid/empty color (the template then keeps the default navy). Returned as
// template.CSS so it is trusted inside the body's style attribute.
func brandCSS(hex string) template.CSS {
	if !hexOK(hex) {
		return ""
	}
	return template.CSS(fmt.Sprintf("--brand:%s;--brand-mid:%s;--brand-deep:%s;", hex, hex, darken(hex, 0.5)))
}
