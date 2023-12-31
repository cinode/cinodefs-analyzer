/*
Copyright © 2023 Bartłomiej Święcki (byo)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cinodefs_analyzer

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cinode/go/pkg/blenc"
	"github.com/cinode/go/pkg/blobtypes"
	"github.com/cinode/go/pkg/cinodefs"
	"github.com/cinode/go/pkg/cinodefs/protobuf"
	"github.com/cinode/go/pkg/common"
	"github.com/cinode/go/pkg/datastore"
	"github.com/cinode/go/pkg/utilities/golang"
	"github.com/cinode/go/pkg/utilities/httpserver"
	"github.com/jbenet/go-base58"
	"google.golang.org/protobuf/proto"
)

type ContentParser struct {
	dataLeft []byte
	err      error
}

func (c *ContentParser) Data(len int) []byte {
	ret := make([]byte, len)
	if c.err != nil {
		return ret
	}
	copied := copy(ret, c.dataLeft)
	c.dataLeft = c.dataLeft[copied:]
	if copied < len {
		c.err = fmt.Errorf("not enough data")
	}
	return ret
}

func (c *ContentParser) Byte() byte     { return c.Data(1)[0] }
func (c *ContentParser) Uint64() uint64 { return binary.BigEndian.Uint64(c.Data(8)) }

type AnalyzerConfig struct {
	DatastoreAddr string
	Entrypoint    string
}

func buildAnalyzerHttpHandler(cfg AnalyzerConfig) (http.Handler, error) {
	ds, err := datastore.FromLocation(cfg.DatastoreAddr)
	if err != nil {
		return nil, fmt.Errorf("could not create main datastore: %w", err)
	}
	be := blenc.FromDatastore(ds)

	var mux http.ServeMux

	mux.Handle("/", http.RedirectHandler(
		"/ep/"+url.PathEscape(cfg.Entrypoint),
		http.StatusTemporaryRedirect),
	)

	type ParsedEP struct {
		Name           string
		EP             *protobuf.Entrypoint
		Str            string
		BN             *common.BlobName
		MimeType       string
		IsDir          bool
		IsLink         bool
		NotValidBefore *time.Time
		NotValidAfter  *time.Time
		Err            string
	}

	type ParsedEPLink struct {
		ParsedEP       `       json:",inline"`
		LinkVersion    uint8  `json:"linkVersion"`
		PublicKey      []byte `json:"publicKey"`
		Nonce          uint64 `json:"nonce"`
		Signature      []byte `json:"signature"`
		ContentVersion uint64 `json:"contentVersion"`
		IV             []byte `json:"iv"`
		LinkDataErr    string `json:"linkDataErr"`
	}

	getParsedEP := func(ep *protobuf.Entrypoint, name string) ParsedEP {
		epBytes, err := proto.Marshal(ep)
		if err != nil {
			return ParsedEP{Err: err.Error()}
		}
		bn, err := common.BlobNameFromBytes(ep.GetBlobName())
		if err != nil {
			return ParsedEP{Err: err.Error()}
		}
		ret := ParsedEP{
			IsDir:    ep.GetMimeType() == cinodefs.CinodeDirMimeType,
			IsLink:   bn.Type() == blobtypes.DynamicLink,
			Name:     name,
			EP:       ep,
			Str:      base58.Encode(epBytes),
			BN:       bn,
			MimeType: ep.GetMimeType(),
		}

		if ep.GetNotValidBeforeUnixMicro() > 0 {
			t := time.UnixMicro(
				ep.GetNotValidBeforeUnixMicro(),
			).UTC()
			ret.NotValidBefore = &t
		}

		if ep.GetNotValidAfterUnixMicro() > 0 {
			t := time.UnixMicro(
				ep.GetNotValidAfterUnixMicro(),
			).UTC()
			ret.NotValidAfter = &t
		}

		return ret
	}

	getParsedEPFromBytes := func(epBytes []byte, name string) ParsedEP {
		ep := protobuf.Entrypoint{}
		err := proto.Unmarshal(epBytes, &ep)
		if err != nil {
			return ParsedEP{Err: err.Error()}
		}
		return getParsedEP(&ep, name)
	}

	getParsedEPFromString := func(epString string, name string) ParsedEP {
		epBytes := base58.Decode(epString)
		if base58.Encode(epBytes) != epString {
			return ParsedEP{Err: "invalid entrypoint - not a base58 data"}
		}
		return getParsedEPFromBytes(epBytes, name)
	}

	type EPData struct {
		EP             ParsedEP
		EPDump         string
		ContentErr     string
		ContentHexDump string
		ContentLen     int
		Link           ParsedEPLink
		DirErr         string
		DirContent     []ParsedEP
		Image          string
		Text           string
		DefaultEP      string
	}

	readRawContent := func(ctx context.Context, ds datastore.DS, bn *common.BlobName) ([]byte, error) {
		r, err := ds.Open(ctx, bn)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	}

	readBlob := func(ctx context.Context, be blenc.BE, ep *protobuf.Entrypoint) ([]byte, error) {
		bn, err := common.BlobNameFromBytes(ep.GetBlobName())
		if err != nil {
			return nil, err
		}
		key := common.BlobKeyFromBytes(ep.KeyInfo.GetKey())
		contentReader, err := be.Open(ctx, bn, key)
		if err != nil {
			return nil, err
		}
		defer contentReader.Close()

		return io.ReadAll(contentReader)
	}

	extractParams := func(ctx context.Context, eps string) EPData {
		pageParams := EPData{
			DefaultEP: cfg.Entrypoint,
		}

		if eps == "" {
			pageParams.EP = ParsedEP{Err: "Missing entrypoint data"}
			return pageParams
		}

		pageParams.EP = getParsedEPFromString(eps, "")
		if pageParams.EP.Err != "" {
			return pageParams
		}

		rawContent, err := readRawContent(ctx, ds, pageParams.EP.BN)
		if err != nil {
			pageParams.ContentErr = err.Error()
			return pageParams
		}

		content, err := readBlob(ctx, be, pageParams.EP.EP)
		if err != nil {
			pageParams.ContentErr = err.Error()
			return pageParams
		}

		const maxBytesDump = 512 * 4
		sb := &strings.Builder{}
		for i := 0; i < len(content) && i < maxBytesDump; i++ {
			fmt.Fprintf(sb, "%02x", uint(content[i]))
			switch {
			case (i+1)%32 == 0:
				sb.WriteString("\n")
			case (i+1)%8 == 0:
				sb.WriteString("  ")
			default:
				sb.WriteString(" ")
			}
		}
		if len(content) > maxBytesDump {
			fmt.Fprintf(sb, ".... (%d more)", len(content)-maxBytesDump)
		}
		pageParams.ContentHexDump = sb.String()
		pageParams.ContentLen = len(content)

		switch {
		case pageParams.EP.IsLink:
			pageParams.Link = ParsedEPLink{
				ParsedEP: getParsedEPFromBytes(content, ""),
			}
			parser := ContentParser{dataLeft: rawContent}
			pageParams.Link.LinkVersion = parser.Byte()
			pageParams.Link.PublicKey = parser.Data(ed25519.PublicKeySize)
			pageParams.Link.Nonce = parser.Uint64()
			pageParams.Link.Signature = parser.Data(ed25519.SignatureSize)
			pageParams.Link.ContentVersion = parser.Uint64()
			ivSize := parser.Byte()
			if ivSize > 0x7F {
				pageParams.Link.LinkDataErr = "invalid iv size"
			} else {
				pageParams.Link.IV = parser.Data(int(ivSize))
			}

		case pageParams.EP.IsDir:
			dir := protobuf.Directory{}
			err = proto.Unmarshal(content, &dir)
			if err != nil {
				pageParams.DirErr = err.Error()
			}
			for _, e := range dir.GetEntries() {
				pageParams.DirContent = append(pageParams.DirContent,
					getParsedEP(e.GetEp(), e.GetName()),
				)
			}

		case strings.HasPrefix(pageParams.EP.MimeType, "image/"):
			pageParams.Image = base64.RawStdEncoding.EncodeToString(content)

		case strings.HasPrefix(pageParams.EP.MimeType, "text/"):
			pageParams.Text = string(content)
		}

		return pageParams
	}

	mux.HandleFunc("/ep/", func(w http.ResponseWriter, r *http.Request) {
		pageParams := extractParams(r.Context(), strings.TrimPrefix(r.URL.Path, "/ep/"))

		err := pageTemplate.ExecuteTemplate(w, "ep.html", &pageParams)
		httpserver.FailResponseOnError(w, err)
	})
	mux.HandleFunc("/api/html/details/", func(w http.ResponseWriter, r *http.Request) {
		pageParams := extractParams(r.Context(), strings.TrimPrefix(r.URL.Path, "/api/html/details/"))

		err := pageTemplate.ExecuteTemplate(w, "ep-detail.html", &pageParams)
		httpserver.FailResponseOnError(w, err)
	})
	mux.HandleFunc("/api/ep/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := extractParams(r.Context(), strings.TrimPrefix(r.URL.Path, "/api/ep/"))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(&data)
	})
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	return &mux, nil
}

//go:embed templates/*.html
var templatesFS embed.FS
var pageTemplate = golang.Must(template.New("cinodefs-analyzer").Funcs(template.FuncMap{
	"toJson": func(v interface{}) string {
		a, _ := json.MarshalIndent(v, "", "  ")
		return string(a)
	},
	"blobTypeString": func(bt common.BlobType) string {
		return blobtypes.ToName(bt)
	},
	"hex": func(buf []byte) string {
		ret := &strings.Builder{}
		for i, b := range buf {
			if i > 0 {
				ret.WriteRune(' ')
			}
			fmt.Fprintf(ret, "%02X", b)
		}
		return ret.String()
	},
}).ParseFS(templatesFS, "templates/*.html"))

//go:embed static
var staticFS embed.FS
