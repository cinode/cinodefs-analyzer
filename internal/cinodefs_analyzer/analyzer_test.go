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
	"github.com/cinode/go/pkg/datastore"
	"github.com/cinode/go/pkg/protobuf"
	"github.com/cinode/go/pkg/structure"
	"github.com/jbenet/go-base58"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/exp/slog"
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

	d := structure.StaticDir{}

	{ // Simple text file with expiration dates
		s.text = "a sample text for testing purposes"
		fl, err := structure.UploadStaticBlob(
			context.Background(),
			s.be,
			strings.NewReader(s.text),
			"text/plain",
			slog.Default(),
		)
		require.NoError(s.T(), err)

		fl.NotValidBeforeUnixMicro = s.timeBefore.UnixMicro()
		fl.NotValidAfterUnixMicro = s.timeAfter.UnixMicro()
		d.SetEntry("testTextFile", fl)
		s.textEP = toEPString(fl)
	}

	{ // Image - don't need true image for that, only the mimetype
		s.imageBytes = []byte{1, 2, 3, 4, 5, 6, 7}
		png, err := structure.UploadStaticBlob(
			context.Background(),
			s.be,
			bytes.NewReader(s.imageBytes),
			"image/png",
			slog.Default(),
		)
		require.NoError(s.T(), err)
		d.SetEntry("testImage", png)
		s.imageEP = toEPString(png)
	}

	{ // Large file
		largeFile, err := structure.UploadStaticBlob(
			context.Background(),
			s.be,
			bytes.NewReader(make([]byte, 12345)),
			"application/octet-stream",
			slog.Default(),
		)
		require.NoError(s.T(), err)
		d.SetEntry("largeFile", largeFile)
		s.largeFileEP = toEPString(largeFile)
	}

	{ // Missing blob, store it in a temporary memory datastore so that it does not exist
		// in the main datastore used during the test
		missingFile, err := structure.UploadStaticBlob(
			context.Background(),
			blenc.FromDatastore(datastore.InMemory()),
			strings.NewReader("file that shall not exist"),
			"text/plain",
			slog.Default(),
		)
		require.NoError(s.T(), err)
		d.SetEntry("missingFile", missingFile)
		s.missingEP = toEPString(missingFile)
	}

	{ // Link to other file
		fl, err := structure.UploadStaticBlob(
			context.Background(),
			s.be,
			strings.NewReader("link target"),
			"text/plain",
			slog.Default(),
		)
		require.NoError(s.T(), err)

		link, _, err := structure.CreateLink(
			context.Background(),
			s.be,
			fl,
		)
		require.NoError(s.T(), err)
		s.linkTargetEP = toEPString(fl)
		s.linkEP = toEPString(link)
	}

	{ // Link to broken blob
		name, key, _, err := s.be.Create(
			context.Background(),
			blobtypes.DynamicLink,
			strings.NewReader("zzzzzzzzzzzz"),
		)
		require.NoError(s.T(), err)

		link := &protobuf.Entrypoint{
			BlobName: name,
			MimeType: "application/broken",
			KeyInfo: &protobuf.KeyInfo{
				Key: key,
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
			BlobName: name,
			MimeType: structure.CinodeDirMimeType,
			KeyInfo: &protobuf.KeyInfo{
				Key: key,
			},
		}
		require.NoError(s.T(), err)
		s.brokenDirEP = toEPString(link)
	}

	{ // Root entrypoint
		epData, err := d.GenerateEntrypoint(context.Background(), s.be)
		require.NoError(s.T(), err)
		s.rootEP = toEPString(epData)
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

func (s *AnalyzerTestSuite) getEpJSON(ep string) map[string]any {
	resp, err := http.Get(s.server.URL + "/api/ep/" + ep)
	require.NoError(s.T(), err)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)

	parsedJson := map[string]any{}
	err = json.Unmarshal(data, &parsedJson)
	require.NoError(s.T(), err)

	return parsedJson
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
	require.Contains(s.T(), data["EPError"].(string), "Missing entrypoint data")
}

func (s *AnalyzerTestSuite) TestNotABase58() {
	body := s.getEpDetailsHtml("not-@#$!@#-a-base58")
	require.Contains(s.T(), body, "not a base58 data")

	data := s.getEpJSON("not-@#$!@#-a-base58")
	require.Contains(s.T(), data["EPError"].(string), "not a base58 data")
}

func (s *AnalyzerTestSuite) TestInvalidEntrypoint() {
	body := s.getEpDetailsHtml("zzzzzzzzzzzzzzzzzzzzzzzzz")
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON("zzzzzzzzzzzzzzzzzzzzzzzzz")
	require.Contains(s.T(), data["EPError"].(string), "cannot parse")
}

func (s *AnalyzerTestSuite) TestDirectoryListing() {
	files := []string{
		"testTextFile",
		"testImage",
		"largeFile",
		"missingFile",
	}

	body := s.getEpDetailsHtml(s.rootEP)
	require.Contains(s.T(), body, s.rootEP)

	for _, f := range files {
		require.Contains(s.T(), body, f)
	}

	data := s.getEpJSON(s.rootEP)
	require.Equal(s.T(), s.rootEP, data["EP"])
	require.Equal(s.T(), true, data["IsDir"])
	for _, e := range data["DirContent"].([]any) {
		require.Contains(s.T(), files, e.(map[string]any)["Name"].(string))
	}
}

func (s *AnalyzerTestSuite) TestTextFile() {
	body := s.getEpDetailsHtml(s.textEP)
	require.Contains(s.T(), body, s.textEP)
	require.Contains(s.T(), body, s.timeAfter.Format(time.RFC3339Nano))
	require.Contains(s.T(), body, s.timeBefore.Format(time.RFC3339Nano))
	require.Contains(s.T(), body, s.text)

	data := s.getEpJSON(s.textEP)
	require.Equal(s.T(), s.textEP, data["EP"])
	require.Equal(s.T(), s.timeBefore.Format(time.RFC3339), data["NotValidBefore"])
	require.Equal(s.T(), s.timeAfter.Format(time.RFC3339), data["NotValidAfter"])
	require.Equal(s.T(), s.text, data["Text"])
}

func (s *AnalyzerTestSuite) TestImage() {
	body := s.getEpDetailsHtml(s.imageEP)
	require.Contains(s.T(), body, s.imageEP)
	require.Contains(s.T(), body, "<img")
	require.Contains(s.T(), body,
		base64.RawStdEncoding.EncodeToString(s.imageBytes),
	)

	data := s.getEpJSON(s.imageEP)
	require.Equal(s.T(), s.imageEP, data["EP"])
	require.Equal(s.T(), base64.RawStdEncoding.EncodeToString(s.imageBytes), data["Image"])
}

func (s *AnalyzerTestSuite) TestLargeFile() {
	body := s.getEpDetailsHtml(s.largeFileEP)
	require.Contains(s.T(), body, s.largeFileEP)
	require.Contains(s.T(), body, fmt.Sprintf("... (%d more)", 12345-512*4))

	data := s.getEpJSON(s.largeFileEP)
	require.Equal(s.T(), s.largeFileEP, data["EP"])
	require.Contains(s.T(), data["ContentHexDump"], fmt.Sprintf("... (%d more)", 12345-512*4))
}

func (s *AnalyzerTestSuite) TestMissingFile() {
	body := s.getEpDetailsHtml(s.missingEP)
	require.Contains(s.T(), body, s.missingEP)
	require.Contains(s.T(), body, "not found")

	data := s.getEpJSON(s.missingEP)
	require.Equal(s.T(), s.missingEP, data["EP"])
	require.Contains(s.T(), data["ContentErr"], "not found")
}

func (s *AnalyzerTestSuite) TestLink() {
	body := s.getEpDetailsHtml(s.linkEP)
	require.Contains(s.T(), body, s.linkEP)
	require.Contains(s.T(), body, "Dynamic link")
	require.Contains(s.T(), body, s.linkTargetEP)

	data := s.getEpJSON(s.linkEP)
	require.Equal(s.T(), s.linkEP, data["EP"])
	require.Equal(s.T(), true, data["IsLink"])
	require.Equal(s.T(), s.linkTargetEP, data["Link"].(map[string]any)["EP"])
}

func (s *AnalyzerTestSuite) TestBrokenLink() {
	body := s.getEpDetailsHtml(s.brokenLinkEP)
	s.T().Logf("Broken link EP: %s", s.brokenLinkEP)
	require.Contains(s.T(), body, s.brokenLinkEP)
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON(s.brokenLinkEP)
	require.Equal(s.T(), s.brokenLinkEP, data["EP"])
	require.Equal(s.T(), true, data["IsLink"])
	require.Contains(s.T(), data["LinkErr"], "cannot parse")
}

func (s *AnalyzerTestSuite) TestBrokenDirectory() {
	body := s.getEpDetailsHtml(s.brokenDirEP)
	s.T().Logf("Broken link EP: %s", s.brokenDirEP)
	require.Contains(s.T(), body, s.brokenDirEP)
	require.Contains(s.T(), body, "cannot parse")

	data := s.getEpJSON(s.brokenDirEP)
	require.Equal(s.T(), s.brokenDirEP, data["EP"])
	require.Contains(s.T(), data["DirErr"], "cannot parse")
}
