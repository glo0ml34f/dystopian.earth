package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type challengeView struct {
	Slug        string
	Title       string
	Audience    string
	Category    string
	Summary     string
	Objectives  []string
	Steps       []string
	FlagFormat  string
	RefreshNote string
	Artifacts   []challengeArtifact
	Palette     []paletteSwatch
	Lore        []string
}

type challengeArtifact struct {
	Label string
	Value string
	Hint  string
	Code  bool
}

type paletteSwatch struct {
	Hex string
}

type arSite struct {
	Name string
	City string
	Lat  float64
	Lon  float64
	Lore string
}

func (s *Server) challenges(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	cycleStart := dailySeed(now)
	refresh := cycleStart.Add(24 * time.Hour)

	hacker := buildHackerChallenge(cycleStart, s.cfg.FlagSecret)
	artist := buildArtistChallenge(cycleStart, s.cfg.FlagSecret)
	ar := buildARChallenge(cycleStart, s.cfg.FlagSecret)

	s.renderTemplate(w, r, "challenges.html", map[string]any{
		"Title":           "Initiation Challenges",
		"Challenges":      []challengeView{hacker, artist, ar},
		"RefreshHuman":    refresh.Format(time.RFC1123),
		"RefreshISO":      refresh.Format(time.RFC3339),
		"CycleDescriptor": cycleStart.Format("2006-01-02"),
		"User":            s.currentUser(r.Context()),
	})
}

func buildHackerChallenge(day time.Time, secret string) challengeView {
	flag := dailyFlag(secret, "hacker", day)
	key := "proxy"
	cipherHex := hex.EncodeToString(repeatingXOR([]byte(flag), []byte(key)))
	signature := signatureFragment(secret, "hacker-log", day, 12)

	return challengeView{
		Slug:     "hacker",
		Title:    "Network Breach Reconstruction",
		Audience: "Hackers",
		Category: "Security Forensics",
		Summary:  "Reassemble an intercepted payload captured during last night's perimeter sweep.",
		Objectives: []string{
			"Identify the transport key reused by the intruder",
			"Undo the cipher layering on the captured packet",
			"Extract the daily rotating flag without altering its casing",
		},
		Steps: []string{
			"The payload uses a repeating-key XOR with the key listed below.",
			"Hex-decode the packet, apply the key, and recover the plaintext.",
			"Submit the decrypted string as your flag in the dystopia{} format.",
		},
		FlagFormat:  "dystopia{hacker-??????????}",
		RefreshNote: "Flag rotates every 24h based on UTC cycle seed.",
		Artifacts: []challengeArtifact{
			{
				Label: "Capture ID",
				Value: fmt.Sprintf("STYX-%s", strings.ToUpper(signature)),
				Hint:  "Ties this capture to the correct day for verification logs.",
			},
			{
				Label: "Repeating Key",
				Value: key,
				Hint:  "Apply as ASCII against the cipher stream.",
				Code:  true,
			},
			{
				Label: "Captured Packet (hex)",
				Value: chunkString(cipherHex, 64),
				Hint:  "Group the bytes for readability before decoding.",
				Code:  true,
			},
		},
		Lore: []string{
			"Once deciphered, swap the flag with an initiate coordinator to mint your invite JWT.",
		},
	}
}

func buildArtistChallenge(day time.Time, secret string) challengeView {
	flag := dailyFlag(secret, "artist", day)
	palette := flagPalette(flag)

	return challengeView{
		Slug:     "artist",
		Title:    "Chromatic Logic Glyph",
		Audience: "Artists",
		Category: "Visual Deduction",
		Summary:  "Decode a color glyph assembled from the day's invite cadence.",
		Objectives: []string{
			"Interpret the swatch stack as ordered RGB triplets",
			"Translate component values to their ASCII counterparts",
			"Reconstruct the glyph without losing punctuation",
		},
		Steps: []string{
			"Each swatch encodes three ASCII characters using its RGB values (R=first char, G=second, B=third).",
			"Convert the hexadecimal channels into characters and read the sequence top to bottom.",
			"Trim any trailing spaces introduced by padding — the resulting string is the flag.",
		},
		FlagFormat:  "dystopia{artist-??????????}",
		RefreshNote: "Swatches regenerate alongside the daily flag.",
		Palette:     palette,
		Lore: []string{
			"Sketch the decoded glyph onto your initiation dossier before requesting your invite JWT.",
		},
	}
}

func buildARChallenge(day time.Time, secret string) challengeView {
	site, shift := selectSite(day, secret)
	coordinateString := fmt.Sprintf("%0.5f,%0.5f", site.Lat, site.Lon)
	scrambled := scrambleDigits(coordinateString, shift)

	return challengeView{
		Slug:     "ar",
		Title:    "Phantom Coordinates Run",
		Audience: "Explorers",
		Category: "Augmented Reality Scout",
		Summary:  "Unscramble geo-coordinates and identify the structure guarding tonight's entrance code.",
		Objectives: []string{
			"Reverse the digit rotation applied to the coordinate string",
			"Plot the recovered latitude and longitude",
			"Name the building located there to claim the flag",
		},
		Steps: []string{
			fmt.Sprintf("Digits were rotated forward by %d (mod 10); reverse the shift.", shift),
			"Reinsert the decimal places exactly as shown and map the point in your AR overlay.",
			"Confirm the structure's proper name — that's the flag you must report.",
		},
		FlagFormat:  site.Name,
		RefreshNote: "Location and shift rotate every 24h.",
		Artifacts: []challengeArtifact{
			{
				Label: "Scrambled Coordinates",
				Value: scrambled,
				Hint:  "Only digits moved; symbols stayed in place.",
				Code:  true,
			},
			{
				Label: "Anchor City",
				Value: site.City,
				Hint:  "Verify you're in the correct hemisphere before decoding the flag.",
			},
		},
		Lore: []string{
			site.Lore,
			"Announce the building name verbatim to the registrar to forge your invite JWT.",
		},
	}
}

func dailySeed(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func dailyFlag(secret, slug string, day time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s|%s", slug, day.Format("2006-01-02"))
	digest := mac.Sum(nil)
	return fmt.Sprintf("dystopia{%s-%s}", slug, hex.EncodeToString(digest)[:10])
}

func signatureFragment(secret, slug string, day time.Time, length int) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s|signature|%s", slug, day.Format(time.RFC3339))
	return hex.EncodeToString(mac.Sum(nil))[:length]
}

func repeatingXOR(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func chunkString(in string, width int) string {
	if width <= 0 || len(in) <= width {
		return in
	}
	var builder strings.Builder
	for i := 0; i < len(in); i += width {
		end := i + width
		if end > len(in) {
			end = len(in)
		}
		builder.WriteString(in[i:end])
		if end < len(in) {
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

func flagPalette(flag string) []paletteSwatch {
	bytes := []byte(flag)
	swatches := make([]paletteSwatch, 0, (len(bytes)+2)/3)
	for i := 0; i < len(bytes); i += 3 {
		chunk := []byte{' ', ' ', ' '}
		copy(chunk, bytes[i:])
		swatches = append(swatches, paletteSwatch{Hex: fmt.Sprintf("#%02X%02X%02X", chunk[0], chunk[1], chunk[2])})
	}
	return swatches
}

func scrambleDigits(input string, shift int) string {
	var builder strings.Builder
	for _, r := range input {
		if r >= '0' && r <= '9' {
			rotated := int(r-'0') + shift
			builder.WriteRune(rune('0' + rotated%10))
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func selectSite(day time.Time, secret string) (arSite, int) {
	sites := []arSite{
		{Name: "The Vessel", City: "New York City, USA", Lat: 40.753813, Lon: -74.002075, Lore: "A honeycomb of stairways reflecting the skyline; find the mirrored heart."},
		{Name: "Svalbard Global Seed Vault", City: "Longyearbyen, Svalbard", Lat: 78.235997, Lon: 15.491347, Lore: "The polar archive where tomorrow's harvest is frozen in time."},
		{Name: "Gardens by the Bay", City: "Singapore", Lat: 1.281568, Lon: 103.863613, Lore: "Supertrees guide you — align your AR overlay with the bio-dome glow."},
		{Name: "Pionen Data Center", City: "Stockholm, Sweden", Lat: 59.314379, Lon: 18.084564, Lore: "A Cold War bunker reborn as a crystalline server garden."},
		{Name: "Miraikan", City: "Tokyo, Japan", Lat: 35.619605, Lon: 139.775326, Lore: "Home of the future museum; the android docent will validate your find."},
		{Name: "Zeitz MOCAA", City: "Cape Town, South Africa", Lat: -33.907781, Lon: 18.421060, Lore: "Carved from grain silos, now storing visions of the continent."},
	}

	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "ar|%s", day.Format("2006-01-02"))
	digest := mac.Sum(nil)
	index := int(digest[0]) % len(sites)
	shift := int(digest[1]%7) + 3
	return sites[index], shift
}
