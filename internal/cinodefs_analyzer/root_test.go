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
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/cinode/go/pkg/utilities/golang"
	"github.com/stretchr/testify/require"
)

func TestRootCmd(t *testing.T) {
	port := 53342 // TODO: Select random free listen port
	cmd := rootCmd()
	cmd.SetArgs([]string{"-p", fmt.Sprint(port)})

	ctx, cancel := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd.ExecuteContext(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", port))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRootCmdInvalidConfig(t *testing.T) {
	golang.SetTestOsArgs(t, "cinode_analyzer", "--datastore", "/non-existing/folder")

	err := Execute()
	require.ErrorContains(t, err, "could not create main datastore")
}
