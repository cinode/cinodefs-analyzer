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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cinode/go/pkg/blenc"
	"github.com/cinode/go/pkg/blobtypes"
	"github.com/cinode/go/pkg/cinodefs"
	"github.com/cinode/go/pkg/cinodefs/protobuf"
	"github.com/cinode/go/pkg/datastore"
	"github.com/jbenet/go-base58"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

func TestBuildAnalyzerHttpHandlerInvalidDatastore(t *testing.T) {
	handler, err := buildAnalyzerHttpHandler(AnalyzerConfig{})
	require.ErrorContains(t, err, "datastore")
	require.Nil(t, handler)
}

type AnalyzerTestSuite struct {
	suite.Suite

	be blenc.BE

	rootEP       string
	textEP       string
	imageEP      string
	largeFileEP  string
	missingEP    string
	linkEP       string
	linkTargetEP string
	brokenLinkEP string
	brokenDirEP  string

	text       string
	imageBytes []byte

	timeBefore time.Time
	timeAfter  time.Time

	server *httptest.Server
}

func TestAnalyzerTestSuite(t *testing.T) {
	suite.Run(t, &AnalyzerTestSuite{})
}

func (s *AnalyzerTestSuite) SetupTest() {
	s.timeBefore = time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	s.timeAfter = time.Date(3000, 6, 7, 8, 9, 1, 0, time.UTC)

	dir := s.T().TempDir()
	ds, err := datastore.FromLocation(dir)
	require.NoError(s.T(), err)
	s.be = blenc.FromDatastore(ds)

	toEPString := func(ep *protobuf.Entrypoint) string {
		epBytes, err := proto.Marshal(ep)
		require.NoError(s.T(), err)
		return base58.Encode(epBytes)
	}

	cfs, err := cinodefs.New(context.Background(), s.be, cinodefs.NewRootStaticDirectory())
	require.NoError(s.T(), err)

	{ // Simple text file with expiration dates
		s.text = "a sample text for testing purposes"

		ep, err := cfs.SetEntryFile(
			context.Background(),
			[]string{"testTextFile"},
			strings.NewReader(s.text),
			cinodefs.SetMimeType("text/plain"),
			// NotValidBeforeUnixMicro = s.timeBefore.UnixMicro()
			// NotValidAfterUnixMicro = s.timeAfter.UnixMicro()
		)
		require.NoError(s.T(), err)
		s.textEP = ep.String()
	}

	{ // Image - don't need true image for that, only the mimetype
		s.imageBytes = []byte{1, 2, 3, 4, 5, 6, 7}
		ep, err := cfs.SetEntryFile(
			context.Background(),
			[]string{"testImage"},
			bytes.NewReader(s.imageBytes),
			cinodefs.SetMimeType("image/png"),
		)
		require.NoError(s.T(), err)
		s.imageEP = ep.String()
	}

	{ // Large file
		ep, err := cfs.SetEntryFile(
			context.Background(),
			[]string{"largeFile"},
			bytes.NewReader(make([]byte, 12345)),
			cinodefs.SetMimeType("application/octet-stream"),
		)
		require.NoError(s.T(), err)
		s.largeFileEP = ep.String()
	}

	{ // Missing blob, store it in a temporary memory datastore so that it does not exist
		// in the main datastore used during the test
		otherFS, err := cinodefs.New(
			context.Background(),
			blenc.FromDatastore(datastore.InMemory()),
			cinodefs.NewRootStaticDirectory(),
		)
		require.NoError(s.T(), err)

		ep, err := otherFS.CreateFileEntrypoint(
			context.Background(),
			strings.NewReader("file that shall not exist"),
			cinodefs.SetMimeType("text/plain"),
		)
		require.NoError(s.T(), err)
		s.missingEP = ep.String()

		err = cfs.SetEntry(
			context.Background(),
			[]string{"missingFile"},
			ep,
		)
		require.NoError(s.T(), err)
	}

	{ // Link to other file
		targetEP, err := cfs.SetEntryFile(
			context.Background(),
			[]string{"link"},
			strings.NewReader("link target"),
		)
		require.NoError(s.T(), err)
		s.linkTargetEP = targetEP.String()

		linkWi, err := cfs.InjectDynamicLink(
			context.Background(),
			[]string{"link"},
		)
		require.NoError(s.T(), err)

		// TODO: Not so easy to get this link's entrypoint, cinodefs should be extended
		protoWI := protobuf.WriterInfo{}
		err = proto.Unmarshal(linkWi.Bytes(), &protoWI)
		require.NoError(s.T(), err)
		protoBytes, err := proto.Marshal(&protobuf.Entrypoint{
			BlobName: protoWI.BlobName,
			KeyInfo:  &protobuf.KeyInfo{Key: protoWI.Key},
		})
		require.NoError(s.T(), err)

		s.linkEP = base58.Encode(protoBytes)
	}

	{ // Link to broken blob
		name, key, _, err := s.be.Create(
			context.Background(),
			blobtypes.DynamicLink,
			strings.NewReader("zzzzzzzzzzzz"),
		)
		require.NoError(s.T(), err)

		link := &protobuf.Entrypoint{
			BlobName: name.Bytes(),
			MimeType: "application/broken",
			KeyInfo: &protobuf.KeyInfo{
				Key: key.Bytes(),
			},
		}
		require.NoError(s.T(), err)
		s.brokenLinkEP = toEPString(link)
	}

	{ // Broken directory
		name, key, _, err := s.be.Create(
			context.Background(),
			blobtypes.Static,
			strings.NewReader("zzzzzzzzzzzz"),
		)
		require.NoError(s.T(), err)

		link := &protobuf.Entrypoint{
			BlobName: name.Bytes(),
			MimeType: cinodefs.CinodeDirMimeType,
			KeyInfo: &protobuf.KeyInfo{
				Key: key.Bytes(),
			},
		}
		require.NoError(s.T(), err)
		s.brokenDirEP = toEPString(link)
	}

	{ // Root entrypoint
		err := cfs.Flush(context.Background())
		require.NoError(s.T(), err)
		ep, err := cfs.RootEntrypoint()
		require.NoError(s.T(), err)
		s.rootEP = ep.String()
	}

	handler, err := buildAnalyzerHttpHandler(AnalyzerConfig{
		DatastoreAddr: dir,
		Entrypoint:    s.rootEP,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), handler)

	s.server = httptest.NewServer(handler)
	s.T().Cleanup(s.server.Close)
}

func (s *AnalyzerTestSuite) getEpDetailsHtml(ep string) string {
	resp, err := http.Get(s.server.URL + "/api/html/details/" + ep)
	require.NoError(s.T(), err)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)

	return string(data)
}

type parsedJson struct {
	t    *testing.T
	data any
}

func (p parsedJson) q(path ...string) any {
	if len(path) == 0 {
		return p.data
	}

	m, isMap := p.data.(map[string]any)
	require.True(p.t, isMap)

	entry, hasEntry := m[path[0]]
	require.True(p.t, hasEntry)

	return parsedJson{t: p.t, data: entry}.q(path[1:]...)
}

func (s *AnalyzerTestSuite) getEpJSON(ep string) parsedJson {
	resp, err := http.Get(s.server.URL + "/api/ep/" + ep)
	require.NoError(s.T(), err)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)

	js := map[string]any{}
	err = json.Unmarshal(data, &js)
	require.NoError(s.T(), err)

	return parsedJson{t: s.T(), data: js}
}

func (s *AnalyzerTestSuite) TestDefaultRedirect() {
	resp, err := http.Get(s.server.URL)
	require.NoError(s.T(), err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)

	err = resp.Body.Close()
	require.NoError(s.T(), err)

	require.Equal(s.T(), s.server.URL+"/ep/"+s.rootEP, resp.Request.URL.String())
	require.Contains(s.T(), string(body), s.rootEP)
}

func (s *AnalyzerTestSuite) TestMissingEntrypoint() {
	body := s.getEpDetailsHtml("")
	require.Contains(s.T(), body, "Missing entrypoint data")

	data := s.getEpJSON("")
	require.Contains(s.T(), data.q("EP", "Err"), "Missing entrypoint data")
}

func (s *AnalyzerTestSuite) TestNotABase58() {
	body := s.getEpDetailsHtml("not-@#$!@#-a-base58")
	require.Contains(s.T(), body, "not a base58 data")

	data := s.getEpJSON("not-@#$!@#-a-base58")
	require.Contains(s.T(), data.q("EP", "Err"), "not a base58 data")
}

func (s *AnalyzerTestSuite) TestInvalidEntrypoint() {
	body := s.getEpDetailsHtml("zzzzzzzzzzzzzzzzzzzzzzzzz")
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON("zzzzzzzzzzzzzzzzzzzzzzzzz")
	require.Contains(s.T(), data.q("EP", "Err"), "cannot parse")
}

func (s *AnalyzerTestSuite) TestDirectoryListing() {
	files := []string{
		"testTextFile",
		"testImage",
		"largeFile",
		"missingFile",
		"link",
	}

	body := s.getEpDetailsHtml(s.rootEP)
	require.Contains(s.T(), body, s.rootEP)

	for _, f := range files {
		require.Contains(s.T(), body, f)
	}

	data := s.getEpJSON(s.rootEP)
	require.Equal(s.T(), s.rootEP, data.q("EP", "Str"))
	require.Equal(s.T(), true, data.q("EP", "IsDir"))
	for _, e := range data.q("DirContent").([]any) {
		require.Contains(s.T(), files, e.(map[string]any)["Name"].(string))
	}
}

func (s *AnalyzerTestSuite) TestTextFile() {
	body := s.getEpDetailsHtml(s.textEP)
	require.Contains(s.T(), body, s.textEP)
	// require.Contains(s.T(), body, s.timeAfter.Format(time.RFC3339Nano))
	// require.Contains(s.T(), body, s.timeBefore.Format(time.RFC3339Nano))
	require.Contains(s.T(), body, s.text)

	data := s.getEpJSON(s.textEP)
	require.Equal(s.T(), s.textEP, data.q("EP", "Str"))
	// require.Equal(s.T(), s.timeBefore.Format(time.RFC3339), data["NotValidBefore"])
	// require.Equal(s.T(), s.timeAfter.Format(time.RFC3339), data["NotValidAfter"])
	require.Equal(s.T(), s.text, data.q("Text"))
}

func (s *AnalyzerTestSuite) TestImage() {
	body := s.getEpDetailsHtml(s.imageEP)
	require.Contains(s.T(), body, s.imageEP)
	require.Contains(s.T(), body, "<img")
	require.Contains(s.T(), body,
		base64.RawStdEncoding.EncodeToString(s.imageBytes),
	)

	data := s.getEpJSON(s.imageEP)
	require.Equal(s.T(), s.imageEP, data.q("EP", "Str"))
	require.Equal(s.T(), base64.RawStdEncoding.EncodeToString(s.imageBytes), data.q("Image"))
}

func (s *AnalyzerTestSuite) TestLargeFile() {
	body := s.getEpDetailsHtml(s.largeFileEP)
	require.Contains(s.T(), body, s.largeFileEP)
	require.Contains(s.T(), body, fmt.Sprintf("... (%d more)", 12345-512*4))

	data := s.getEpJSON(s.largeFileEP)
	require.Equal(s.T(), s.largeFileEP, data.q("EP", "Str"))
	require.Contains(s.T(), data.q("ContentHexDump"), fmt.Sprintf("... (%d more)", 12345-512*4))
}

func (s *AnalyzerTestSuite) TestMissingFile() {
	body := s.getEpDetailsHtml(s.missingEP)
	require.Contains(s.T(), body, s.missingEP)
	require.Contains(s.T(), body, "not found")

	data := s.getEpJSON(s.missingEP)
	require.Equal(s.T(), s.missingEP, data.q("EP", "Str"))
	require.Contains(s.T(), data.q("ContentErr"), "not found")
}

func (s *AnalyzerTestSuite) TestLink() {
	body := s.getEpDetailsHtml(s.linkEP)
	require.Contains(s.T(), body, s.linkEP)
	require.Contains(s.T(), body, "Dynamic link")
	require.Contains(s.T(), body, s.linkTargetEP)

	data := s.getEpJSON(s.linkEP)
	require.Equal(s.T(), s.linkEP, data.q("EP", "Str"))
	require.Equal(s.T(), true, data.q("EP", "IsLink"))
	require.Equal(s.T(), s.linkTargetEP, data.q("Link", "Str"))
}

func (s *AnalyzerTestSuite) TestBrokenLink() {
	body := s.getEpDetailsHtml(s.brokenLinkEP)
	s.T().Logf("Broken link EP: %s", s.brokenLinkEP)
	require.Contains(s.T(), body, s.brokenLinkEP)
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON(s.brokenLinkEP)
	require.Equal(s.T(), s.brokenLinkEP, data.q("EP", "Str"))
	require.Equal(s.T(), true, data.q("EP", "IsLink"))
	require.Contains(s.T(), data.q("Link", "Err"), "cannot parse")
}

func (s *AnalyzerTestSuite) TestBrokenDirectory() {
	body := s.getEpDetailsHtml(s.brokenDirEP)
	s.T().Logf("Broken link EP: %s", s.brokenDirEP)
	require.Contains(s.T(), body, s.brokenDirEP)
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON(s.brokenDirEP)
	require.Equal(s.T(), s.brokenDirEP, data.q("EP", "Str"))
	require.Contains(s.T(), data.q("DirErr"), "cannot parse")
}
