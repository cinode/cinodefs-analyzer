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
	"embed"
	"encoding/base64"
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
	"github.com/cinode/go/pkg/common"
	"github.com/cinode/go/pkg/datastore"
	"github.com/cinode/go/pkg/protobuf"
	"github.com/cinode/go/pkg/structure"
	"github.com/cinode/go/pkg/utilities/golang"
	"github.com/cinode/go/pkg/utilities/httpserver"
	"github.com/jbenet/go-base58"
	"google.golang.org/protobuf/proto"
)

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
		Name     string
		EP       string
		MimeType string
		IsDir    bool
		IsLink   bool
	}

	getParsedEP := func(ep *protobuf.Entrypoint, name string) ParsedEP {
		epBytes, _ := proto.Marshal(ep)
		return ParsedEP{
			IsDir:    ep.GetMimeType() == structure.CinodeDirMimeType,
			IsLink:   common.BlobName(ep.GetBlobName()).Type() == blobtypes.DynamicLink,
			Name:     name,
			EP:       base58.Encode(epBytes),
			MimeType: ep.GetMimeType(),
		}
	}

	type EPData struct {
		EP             string
		EPError        string
		EPData         *protobuf.Entrypoint
		BlobName       string
		BlobType       string
		NotValidBefore string
		NotValidAfter  string
		KeyInfo        string
		EPDump         string
		ContentErr     string
		ContentHexDump string
		ContentLen     int
		IsLink         bool
		IsDir          bool
		LinkErr        string
		Link           ParsedEP
		DirErr         string
		DirContent     []ParsedEP
		Image          string
		Text           string
		DefaultEP      string
	}

	readBlob := func(ctx context.Context, be blenc.BE, ep *protobuf.Entrypoint) ([]byte, error) {
		contentReader, err := be.Open(ctx, common.BlobName(ep.BlobName), ep.KeyInfo.Key)
		if err != nil {
			return nil, err
		}
		defer contentReader.Close()

		return io.ReadAll(contentReader)
	}

	extractParams := func(ctx context.Context, eps string) EPData {
		pageParams := EPData{
			EP:        eps,
			DefaultEP: cfg.Entrypoint,
		}

		if pageParams.EP == "" {
			pageParams.EPError = "Missing entrypoint data"
			return pageParams
		}

		epBytes := base58.Decode(pageParams.EP)
		if base58.Encode(epBytes) != pageParams.EP {
			pageParams.EPError = "Invalid entrypoint - not a base58 data"
			return pageParams
		}

		ep, err := protobuf.EntryPointFromBytes(epBytes)
		if err != nil {
			pageParams.EPError = err.Error()
			return pageParams
		}

		pageParams.EPData = ep
		bn := common.BlobName(ep.GetBlobName())
		pageParams.BlobName = bn.String()
		pageParams.BlobType = blobtypes.ToName(bn.Type())

		if ep.GetNotValidBeforeUnixMicro() > 0 {
			pageParams.NotValidBefore = time.UnixMicro(
				ep.GetNotValidBeforeUnixMicro(),
			).UTC().Format(time.RFC3339Nano)
		}

		if ep.GetNotValidAfterUnixMicro() > 0 {
			pageParams.NotValidAfter = time.UnixMicro(
				ep.GetNotValidAfterUnixMicro(),
			).UTC().Format(time.RFC3339Nano)
		}

		keyInfo, _ := json.MarshalIndent(ep.KeyInfo, "", "  ")
		pageParams.KeyInfo = string(keyInfo)

		epDump, _ := json.MarshalIndent(&ep, "", "  ")
		pageParams.EPDump = string(epDump)

		content, err := readBlob(ctx, be, ep)
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

		switch bn.Type() {
		case blobtypes.DynamicLink:
			pageParams.IsLink = true
			linkEP := protobuf.Entrypoint{}
			err := proto.Unmarshal(content, &linkEP)
			if err != nil {
				pageParams.LinkErr = err.Error()
			} else {
				pageParams.Link = getParsedEP(&linkEP, "")
			}

		case blobtypes.Static:
			if ep.MimeType == structure.CinodeDirMimeType {

				dir := protobuf.Directory{}

				err = proto.Unmarshal(content, &dir)
				if err != nil {
					pageParams.DirErr = err.Error()
				}
				pageParams.IsDir = true
				for _, e := range dir.GetEntries() {
					pageParams.DirContent = append(pageParams.DirContent, getParsedEP(e.GetEp(), e.GetName()))
				}
			} else if strings.HasPrefix(ep.MimeType, "image/") {
				pageParams.Image = base64.RawStdEncoding.EncodeToString(content)
			} else if strings.HasPrefix(ep.MimeType, "text/") {
				pageParams.Text = string(content)
			}
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
var pageTemplate = golang.Must(template.ParseFS(templatesFS, "templates/*.html"))

//go:embed static
var staticFS embed.FS
