package proxy

import (
	"fmt"
	mathrand "math/rand"
	"regexp"
	"strconv"
	"strings"
)

// BrowserProfile holds a consistent set of browser identity fields.
// All fields must be coherent — VK checks sec-ch-ua vs User-Agent consistency.
type BrowserProfile struct {
	UserAgent     string
	Platform      string // "Windows", "macOS", "Linux"
	ChromeVersion int    // major version, e.g., 146
}

// SecChUA returns the sec-ch-ua header matching this profile.
func (p BrowserProfile) SecChUA() string {
	return fmt.Sprintf(`"Chromium";v="%d", "Not-A.Brand";v="24", "Google Chrome";v="%d"`, p.ChromeVersion, p.ChromeVersion)
}

// SecChUAPlatform returns the sec-ch-ua-platform header.
func (p BrowserProfile) SecChUAPlatform() string {
	switch p.Platform {
	case "macOS":
		return `"macOS"`
	case "Linux":
		return `"Linux"`
	default:
		return `"Windows"`
	}
}

var browserProfiles = []BrowserProfile{
	// Chrome on Windows
	{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 146},
	{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 145},
	{UserAgent: "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 146},
	{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 144},
	{UserAgent: "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 145},
	{UserAgent: "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 144},
	{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36", Platform: "Windows", ChromeVersion: 143},

	// Chrome on macOS
	{UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", Platform: "macOS", ChromeVersion: 146},
	{UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", Platform: "macOS", ChromeVersion: 145},
	{UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", Platform: "macOS", ChromeVersion: 146},

	// Chrome on Linux
	{UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", Platform: "Linux", ChromeVersion: 146},
	{UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", Platform: "Linux", ChromeVersion: 145},
	{UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36", Platform: "Linux", ChromeVersion: 144},
}

// userAgentProfiles kept for backward compatibility (creds.go uses it)
var userAgentProfiles []string

func init() {
	for _, p := range browserProfiles {
		userAgentProfiles = append(userAgentProfiles, p.UserAgent)
	}
}

// randomUserAgent returns a random User-Agent string from the profiles list.
func randomUserAgent() string {
	return userAgentProfiles[mathrand.Intn(len(userAgentProfiles))]
}

// randomBrowserProfile returns a full consistent browser profile.
var _ = randomBrowserProfile

func randomBrowserProfile() BrowserProfile {
	return browserProfiles[mathrand.Intn(len(browserProfiles))]
}

// profileForUA finds the BrowserProfile matching a given UA string.
// Falls back to extracting version from the UA if no exact match found.
func profileForUA(ua string) BrowserProfile {
	for _, p := range browserProfiles {
		if p.UserAgent == ua {
			return p
		}
	}
	// Fallback: parse from UA
	p := BrowserProfile{UserAgent: ua, Platform: "Windows", ChromeVersion: 146}
	re := regexp.MustCompile(`Chrome/(\d+)`)
	if m := re.FindStringSubmatch(ua); len(m) >= 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			p.ChromeVersion = v
		}
	}
	if contains(ua, "Macintosh") {
		p.Platform = "macOS"
	} else if contains(ua, "Linux") || contains(ua, "X11") {
		p.Platform = "Linux"
	}
	return p
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
