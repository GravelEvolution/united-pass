package captcha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

const (
	FirstPartyImageProviderName = "moonstone_image_digits"
	firstPartyDigitCount        = 5
	firstPartyImageWidth        = 286
	firstPartyImageHeight       = 104
	maxFirstPartyImageDataURL   = 32 << 10
)

// FirstPartyImageStore keeps the short-lived answer behind an opaque provider
// challenge ID. The answer never enters the browser-facing challenge payload.
type FirstPartyImageStore interface {
	Create(context.Context, string, string, time.Duration) error
	ConsumeIfMatches(context.Context, string, string) (bool, error)
}

type FirstPartyImageConfig struct {
	Store  FirstPartyImageStore
	TTL    time.Duration
	Random io.Reader
}

type FirstPartyImage struct {
	store  FirstPartyImageStore
	ttl    time.Duration
	random io.Reader
}

type firstPartyImagePublicPayload struct {
	ImageDataURL string `json:"imageDataUrl"`
	Digits       int    `json:"digits"`
}

func NewFirstPartyImage(cfg FirstPartyImageConfig) (*FirstPartyImage, error) {
	if cfg.Store == nil || cfg.TTL <= 0 || cfg.TTL > 15*time.Minute {
		return nil, errors.New("first-party image CAPTCHA requires a store and a bounded TTL")
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return &FirstPartyImage{store: cfg.Store, ttl: cfg.TTL, random: random}, nil
}

func (p *FirstPartyImage) Name() string { return FirstPartyImageProviderName }

func (p *FirstPartyImage) Available(ctx context.Context, region riskdefense.ProviderRegion) bool {
	return p != nil &&
		p.store != nil &&
		ctx.Err() == nil &&
		(region == riskdefense.ProviderRegionMainlandChina || region == riskdefense.ProviderRegionGlobal)
}

func (p *FirstPartyImage) Begin(ctx context.Context, operation riskdefense.Operation) (riskdefense.ProviderChallenge, error) {
	if p == nil || p.store == nil || ctx.Err() != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	if _, err := providerAction(operation); err != nil {
		return riskdefense.ProviderChallenge{}, err
	}
	answer, err := randomDigits(p.random, firstPartyDigitCount)
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	challengeID, err := randomBase64URL(p.random, 32)
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	imageDataURL, err := renderDigitImageDataURL(answer, p.random)
	if err != nil || len(imageDataURL) > maxFirstPartyImageDataURL {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	if err := p.store.Create(ctx, challengeID, answer, p.ttl); err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	payload, err := json.Marshal(firstPartyImagePublicPayload{
		ImageDataURL: imageDataURL,
		Digits:       firstPartyDigitCount,
	})
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	return riskdefense.ProviderChallenge{
		ID:            challengeID,
		Provider:      p.Name(),
		PublicPayload: payload,
	}, nil
}

func (p *FirstPartyImage) Verify(ctx context.Context, challengeID, proof string) error {
	if p == nil || p.store == nil || len(challengeID) < 32 || len(challengeID) > 128 {
		return riskdefense.ErrInvalidProof
	}
	answer, ok := normalizeDigitProof(proof, firstPartyDigitCount)
	if !ok {
		return riskdefense.ErrInvalidProof
	}
	matched, err := p.store.ConsumeIfMatches(ctx, challengeID, answer)
	if err != nil {
		return riskdefense.ErrUnavailable
	}
	if !matched {
		return riskdefense.ErrInvalidProof
	}
	return nil
}

func randomDigits(source io.Reader, count int) (string, error) {
	if source == nil || count < 1 || count > 8 {
		return "", errors.New("invalid digit source")
	}
	var output strings.Builder
	output.Grow(count)
	buffer := []byte{0}
	for output.Len() < count {
		if _, err := io.ReadFull(source, buffer); err != nil {
			return "", err
		}
		// Reject the top six byte values so every digit has the same probability.
		if buffer[0] >= 250 {
			continue
		}
		output.WriteByte('0' + buffer[0]%10)
	}
	return output.String(), nil
}

func randomBase64URL(source io.Reader, size int) (string, error) {
	if source == nil || size < 16 || size > 64 {
		return "", errors.New("invalid random token source")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func normalizeDigitProof(value string, expected int) (string, bool) {
	value = strings.TrimSpace(value)
	var output strings.Builder
	output.Grow(expected)
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
			output.WriteRune(character)
		case character >= '０' && character <= '９':
			output.WriteRune('0' + (character - '０'))
		case unicode.IsSpace(character):
			continue
		default:
			return "", false
		}
	}
	return output.String(), output.Len() == expected
}

// renderDigitImageDataURL rasterizes a small bitmap alphabet with fresh
// cryptographic jitter, shear, rotation, scale and noise. The browser receives
// PNG pixels only, never the source glyph/path geometry or plaintext answer.
// This is deliberately a modest first-party fallback, not a claim that image
// recognition alone can defeat a determined adversary.
func renderDigitImageDataURL(answer string, source io.Reader) (string, error) {
	if normalized, ok := normalizeDigitProof(answer, firstPartyDigitCount); !ok || normalized != answer {
		return "", errors.New("invalid image answer")
	}
	if source == nil {
		return "", errors.New("invalid image random source")
	}
	canvas := image.NewRGBA(image.Rect(0, 0, firstPartyImageWidth, firstPartyImageHeight))
	background := color.RGBA{R: 17, G: 19, B: 24, A: 255}
	for y := 0; y < firstPartyImageHeight; y++ {
		for x := 0; x < firstPartyImageWidth; x++ {
			canvas.SetRGBA(x, y, background)
		}
	}

	var seedBytes [8]byte
	if _, err := io.ReadFull(source, seedBytes[:]); err != nil {
		return "", err
	}
	noise := binary.BigEndian.Uint64(seedBytes[:])
	if noise == 0 {
		noise = 0x9e3779b97f4a7c15
	}
	nextNoise := func() uint64 {
		noise ^= noise << 13
		noise ^= noise >> 7
		noise ^= noise << 17
		return noise
	}
	for sample := 0; sample < 1300; sample++ {
		value := nextNoise()
		x := int(value % firstPartyImageWidth)
		y := int((value >> 16) % firstPartyImageHeight)
		shade := uint8(24 + (value>>32)%24)
		canvas.SetRGBA(x, y, color.RGBA{R: shade, G: shade, B: shade + 3, A: 255})
	}

	lineRandom := make([]byte, 16)
	if _, err := io.ReadFull(source, lineRandom); err != nil {
		return "", err
	}
	for line := 0; line < 4; line++ {
		y0 := 10 + int(lineRandom[line*4])%84
		y1 := 10 + int(lineRandom[line*4+1])%84
		x0 := -12 + int(lineRandom[line*4+2])%26
		x1 := firstPartyImageWidth - 14 + int(lineRandom[line*4+3])%26
		drawRasterLine(canvas, x0, y0, x1, y1, color.RGBA{R: 103, G: 55, B: 38, A: 255}, 1)
	}

	for digitIndex, character := range answer {
		glyph, ok := digitGlyphs[character]
		if !ok {
			return "", errors.New("unsupported image digit")
		}
		var transform [5]byte
		if _, err := io.ReadFull(source, transform[:]); err != nil {
			return "", err
		}
		centerX := float64(39 + digitIndex*52 + int(transform[0]%9) - 4)
		centerY := float64(50 + int(transform[1]%11) - 5)
		scaleX := 7.0 + float64(transform[2]%4)*0.55
		scaleY := 9.2 + float64(transform[3]%4)*0.65
		angle := (float64(int(transform[4])-128) / 128.0) * 0.14
		shear := (float64(int(transform[0])-128) / 128.0) * 0.16
		cosine, sine := math.Cos(angle), math.Sin(angle)
		for row, bits := range glyph {
			for column := 0; column < 5; column++ {
				if bits&(1<<uint(4-column)) == 0 {
					continue
				}
				relativeX := (float64(column) - 2.0 + shear*(float64(row)-3.0)) * scaleX
				relativeY := (float64(row) - 3.0) * scaleY
				x := centerX + relativeX*cosine - relativeY*sine
				y := centerY + relativeX*sine + relativeY*cosine
				drawRasterBlob(canvas, int(math.Round(x)), int(math.Round(y)), 4+int(transform[2]%2), 5+int(transform[3]%2), color.RGBA{R: 246, G: 240, B: 223, A: 255})
			}
		}
	}

	var encoded bytes.Buffer
	if err := png.Encode(&encoded, canvas); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(encoded.Bytes()), nil
}

func drawRasterBlob(canvas *image.RGBA, centerX, centerY, radiusX, radiusY int, fill color.RGBA) {
	for y := -radiusY; y <= radiusY; y++ {
		for x := -radiusX; x <= radiusX; x++ {
			if x*x*radiusY*radiusY+y*y*radiusX*radiusX > radiusX*radiusX*radiusY*radiusY {
				continue
			}
			canvas.SetRGBA(centerX+x, centerY+y, fill)
		}
	}
}

func drawRasterLine(canvas *image.RGBA, x0, y0, x1, y1 int, stroke color.RGBA, width int) {
	deltaX := int(math.Abs(float64(x1 - x0)))
	stepX := -1
	if x0 < x1 {
		stepX = 1
	}
	deltaY := -int(math.Abs(float64(y1 - y0)))
	stepY := -1
	if y0 < y1 {
		stepY = 1
	}
	err := deltaX + deltaY
	for {
		drawRasterBlob(canvas, x0, y0, width, width, stroke)
		if x0 == x1 && y0 == y1 {
			return
		}
		twice := 2 * err
		if twice >= deltaY {
			err += deltaY
			x0 += stepX
		}
		if twice <= deltaX {
			err += deltaX
			y0 += stepY
		}
	}
}

var digitGlyphs = map[rune][7]uint8{
	'0': {0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110},
	'1': {0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
	'2': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	'3': {0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110},
	'4': {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
	'5': {0b11111, 0b10000, 0b10000, 0b11110, 0b00001, 0b00001, 0b11110},
	'6': {0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
	'7': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
	'8': {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
	'9': {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b11100},
}
