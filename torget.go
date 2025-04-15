package main

/*
	torget is a fast large file downloader over locally installed Tor
	Copyright © 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type chunk struct {
	start   int64
	length  int64
	circuit int
	bytes   int64
	since   time.Time
	cancel  context.CancelFunc
}

type State struct {
	ctx         context.Context
	src         string
	dst         string
	bytesTotal  int64
	bytesPrev   int64
	circuits    int
	minLifetime time.Duration
	verbose     bool
	userAgent   string // Added User-Agent field
	chunks      []chunk
	done        chan int
	log         chan string
	terminal    bool
	rwmutex     sync.RWMutex
}

const torBlock = 8000 // the longest plain text block in Tor

// Custom transport to inject User-Agent
type userAgentTransport struct {
	baseTransport http.RoundTripper
	userAgent     string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	// If baseTransport is nil, use http.DefaultTransport
	transport := t.baseTransport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}

func httpClient(user string, ua string) *http.Client { // Added ua parameter
	proxyUrl, _ := url.Parse("socks5://" + user + ":" + user + "@127.0.0.1:9050/")
	baseTransport := &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
	// Wrap the base transport
	customTransport := &userAgentTransport{
		baseTransport: baseTransport,
		userAgent:     ua,
	}
	return &http.Client{
		Transport: customTransport, // Use the custom transport
	}
}

func NewState(ctx context.Context, circuits int, minLifetime int, verbose bool, userAgent string) *State { // Added userAgent parameter
	var s State
	s.circuits = circuits
	s.minLifetime = time.Duration(minLifetime) * time.Second
	s.userAgent = userAgent // Store userAgent
	s.verbose = verbose
	s.chunks = make([]chunk, s.circuits)
	s.ctx = ctx
	s.done = make(chan int)
	s.log = make(chan string, 10)
	st, _ := os.Stdout.Stat()
	s.terminal = st.Mode()&os.ModeCharDevice == os.ModeCharDevice
	return &s
}

func (s *State) printPermanent(txt string) {
	if s.terminal {
		fmt.Printf("\r%-40s\n", txt)
	} else {
		fmt.Println(txt)
	}
}

func (s *State) printTemporary(txt string) {
	if s.terminal {
		fmt.Printf("\r%-40s", txt)
	}
}

func (s *State) chunkInit(id int) (client *http.Client, req *http.Request) {
	s.chunks[id].bytes = 0
	s.chunks[id].since = time.Now()
	ctx, cancel := context.WithCancel(s.ctx)
	s.chunks[id].cancel = cancel
	// Pass userAgent to httpClient
	client = httpClient(fmt.Sprintf("tg%d", s.chunks[id].circuit), s.userAgent)
	req, _ = http.NewRequestWithContext(ctx, "GET", s.src, nil)
	// User-Agent is now set by the custom transport in httpClient
	req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d",
		s.chunks[id].start, s.chunks[id].start+s.chunks[id].length-1))
	return
}

func (s *State) chunkFetch(id int, client *http.Client, req *http.Request) {
	defer func() {
		s.done <- id
	}()

	if s.verbose {
		err := s.getExitNode(id, client)
		if err != nil {
			s.log <- fmt.Sprintf("getExitNode: %s", err.Error())
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		s.log <- fmt.Sprintf("Client Do: %s", err.Error())
		return
	}
	if resp.Body == nil {
		s.log <- "Client Do: No response body"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		s.log <- fmt.Sprintf("Client Do: Unexpected HTTP status: %d", resp.StatusCode)
		return
	}

	// open the output file
	file, err := os.OpenFile(s.dst, os.O_WRONLY, 0)
	defer file.Close()
	if err != nil {
		s.log <- fmt.Sprintf("os OpenFile: %s", err.Error())
		return
	}
	_, err = file.Seek(s.chunks[id].start, io.SeekStart)
	if err != nil {
		s.log <- fmt.Sprintf("File Seek: %s", err.Error())
		return
	}

	// copy network data to the output file
	buffer := make([]byte, torBlock)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			file.Write(buffer[:n])
			// enough to RLock(), as we only modify our own chunk
			s.rwmutex.RLock()
			if int64(n) < s.chunks[id].length {
				s.chunks[id].start += int64(n)
				s.chunks[id].length -= int64(n)
				s.chunks[id].bytes += int64(n)
			} else {
				s.chunks[id].length = 0
			}
			s.rwmutex.RUnlock()
			if s.chunks[id].length == 0 {
				break
			}
		}
		if err != nil {
			s.log <- fmt.Sprintf("ReadCloser Read: %s", err.Error())
			break
		}
	}
}

func (s *State) getExitNode(id int, client *http.Client) error {
	req, err := http.NewRequest(http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return fmt.Errorf("http NewRequest: %s", err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("client Do: %s", err.Error())
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("client Do: Unexpected HTTP status: %d", resp.StatusCode)
	}
	if resp.Body == nil {
		return fmt.Errorf("client Do: No response body")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("io ReadAll: %s", err.Error())
	}

	s.log <- fmt.Sprintf("Circuit #%d: Exit node: %s", id, body)
	return nil
}

func (s *State) printLogs() {
	n := len(s.log)
	logs := make([]string, n+1)
	for i := 0; i < n; i++ {
		logs[i] = <-s.log
	}
	logs[n] = "stop" // not an expected log line
	sort.Strings(logs)
	prevLog := "start" // not an expected log line
	cnt := 0
	for _, log := range logs {
		if log == prevLog {
			cnt++
		} else {
			if cnt > 0 {
				if cnt > 1 {
					prevLog = fmt.Sprintf("%s (%d times)", prevLog, cnt)
				}
				s.printPermanent(prevLog)
			}
			prevLog = log
			cnt = 1
		}
	}
}

func (s *State) ignoreLogs() {
	for len(s.log) > 0 {
		<-s.log
	}
}

func (s *State) statusLine() (status string) {
	// calculate bytes transferred since the previous invocation
	curr := s.bytesTotal
	s.rwmutex.RLock()
	for id := 0; id < s.circuits; id++ {
		curr -= s.chunks[id].length
	}
	s.rwmutex.RUnlock()

	if curr == s.bytesPrev {
		status = fmt.Sprintf("%6.2f%% done, stalled",
			100*float32(curr)/float32(s.bytesTotal))
	} else {
		speed := float32(curr-s.bytesPrev) / 1000
		prefix := "K"
		if speed >= 1000 {
			speed /= 1000
			prefix = "M"
		}
		if speed >= 1000 {
			speed /= 1000
			prefix = "G"
		}
		seconds := (s.bytesTotal - curr) / (curr - s.bytesPrev)
		status = fmt.Sprintf("%6.2f%% done, %6.2f %sB/s, ETA %d:%02d:%02d",
			100*float32(curr)/float32(s.bytesTotal),
			speed, prefix,
			seconds/3600, seconds/60%60, seconds%60)
	}

	s.bytesPrev = curr
	return
}

func (s *State) progress() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.verbose {
				s.printLogs()
			} else {
				s.ignoreLogs()
			}
			s.printTemporary(s.statusLine())
		case <-s.ctx.Done(): // Check context cancellation
			s.printPermanent("Progress reporting stopped.")
			return // Exit progress goroutine when context is cancelled
		}
	}
}

func (s *State) darwin() { // kill the worst performing circuit
		} else {
			s.ignoreLogs()
		}
		s.printTemporary(s.statusLine())
	}
}

func (s *State) darwin() { // kill the worst performing circuit
	victim := -1
	var slowest float64
	now := time.Now()

	s.rwmutex.RLock()
	for id := 0; id < s.circuits; id++ {
		if s.chunks[id].cancel == nil {
			continue
		}
		eplased := now.Sub(s.chunks[id].since)
		if eplased < s.minLifetime {
			continue
		}
		throughput := float64(s.chunks[id].bytes) / eplased.Seconds()
		if victim >= 0 && throughput >= slowest {
			continue
		}
		victim = id
		slowest = throughput
	}
	if victim >= 0 {
		// fmt.Printf("killing %5.1fs %5.1fkB/s",
		//	now.Sub(s.chunks[victim].since).Seconds(), slowest/1024.0)
		s.chunks[victim].cancel()
		s.chunks[victim].cancel = nil
	}
	s.rwmutex.RUnlock()
}

// downloadFileInternal handles the download of a single file using multiple circuits.
// It's the refactored core logic from the original Fetch method.
func (s *State) downloadFileInternal(srcUrl *url.URL, destinationPath string) error {
	s.src = srcUrl.String()
	s.dst = destinationPath

	s.printPermanent(fmt.Sprintf("Downloading: %s -> %s", s.src, s.dst))

	// get the target length
	client := httpClient("torget_meta", s.userAgent) // Use a dedicated user for metadata fetching
	getReq, err := http.NewRequest("GET", s.src, nil)
	if err != nil {
		return fmt.Errorf("failed to create initial GET request for %s: %w", s.src, err)
	}
	resp, err := client.Do(getReq)
	if err != nil {
		// Check if it's a context cancellation error (e.g., user interruption)
		if err == context.Canceled {
			return fmt.Errorf("download cancelled by user")
		}
		return fmt.Errorf("initial GET request failed for %s: %w", s.src, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("initial GET request for %s returned non-success status: %d %s\nResponse body: %s", s.src, resp.StatusCode, resp.Status, string(bodyBytes))
	}

	if resp.ContentLength <= 0 {
		// Allow 0-byte files
		if resp.ContentLength == 0 {
			s.printPermanent(fmt.Sprintf("File %s is 0 bytes. Creating empty file.", s.dst))
			file, err := os.Create(s.dst)
			if err != nil {
				return fmt.Errorf("failed to create 0-byte file %s: %w", s.dst, err)
			}
			file.Close()
			return nil // Successfully "downloaded" 0-byte file
		}
		return fmt.Errorf("failed to retrieve download length for %s (Content-Length: %d)", s.src, resp.ContentLength)
	}
	s.bytesTotal = resp.ContentLength
	s.bytesPrev = 0 // Reset for progress calculation
	s.printPermanent(fmt.Sprintf("Download length: %d bytes", s.bytesTotal))

	// create the output file directory if it doesn't exist
	dir := filepath.Dir(s.dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// create the output file
	file, err := os.Create(s.dst)
	if file != nil {
		file.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", s.dst, err)
	}

	// Reset chunks state for the new file
	s.chunks = make([]chunk, s.circuits) // Reinitialize chunks slice
	chunkLen := s.bytesTotal / int64(s.circuits)
	seq := 0
	for id := 0; id < s.circuits; id++ {
		s.chunks[id].start = int64(id) * chunkLen
		s.chunks[id].length = chunkLen
		s.chunks[id].circuit = seq
		seq++
		// Reset other chunk fields
		s.chunks[id].bytes = 0
		s.chunks[id].since = time.Time{}
		s.chunks[id].cancel = nil
	}
	s.chunks[s.circuits-1].length += s.bytesTotal % int64(s.circuits) // Adjust last chunk length

	// Reset done channel
	s.done = make(chan int) // Create a new channel for this download

	// Use a context specific to this download
	downloadCtx, cancelDownload := context.WithCancel(s.ctx)
	defer cancelDownload() // Ensure cancellation propagates if function returns early
	originalCtx := s.ctx   // Store original context
	s.ctx = downloadCtx    // Update state's context for chunk operations
	defer func() { s.ctx = originalCtx }() // Restore original context when done

	// spawn initial fetchers
	progressDone := make(chan struct{})
	go func() {
		s.progress() // progress needs to respect the downloadCtx
		close(progressDone)
	}()

	fetcherWg := sync.WaitGroup{}
	initialFetchDone := make(chan bool, s.circuits) // Buffered channel

	fetcherWg.Add(s.circuits) // Add count before starting goroutines
	go func() {
		for id := 0; id < s.circuits; id++ {
			// Need to capture id in loop variable for goroutine
			currentID := id
			go func() {
				defer fetcherWg.Done()
				// Check context before starting
				select {
				case <-s.ctx.Done():
					s.log <- fmt.Sprintf("Initial fetch for chunk %d cancelled before start", currentID)
					initialFetchDone <- false
					return
				default:
				}
				client, req := s.chunkInit(currentID) // Use captured currentID
				// Check context again before fetching
				select {
				case <-s.ctx.Done():
					s.log <- fmt.Sprintf("Initial fetch for chunk %d cancelled before Do", currentID)
					initialFetchDone <- false
					return
				default:
				}
				go s.chunkFetch(currentID, client, req) // Use captured currentID
				initialFetchDone <- true
			}()
			// Check context before sleeping
			select {
			case <-s.ctx.Done():
				s.log <- "Download cancelled during initial fetcher spawn"
				// Signal remaining fetchers not started
				for j := id + 1; j < s.circuits; j++ {
					initialFetchDone <- false
					fetcherWg.Done() // Decrement waitgroup for goroutines not started
				}
				return // Exit the spawner goroutine
			case <-time.After(499 * time.Millisecond): // be gentle to the local tor daemon
			}
		}
	}()

	// Wait for all initial fetchers to be launched or cancelled
	initialFetchesStarted := 0
	initialFetchesCancelled := 0
	for i := 0; i < s.circuits; i++ {
		if <-initialFetchDone {
			initialFetchesStarted++
		} else {
			initialFetchesCancelled++
		}
	}
	s.log <- fmt.Sprintf("Initial fetchers: %d started, %d cancelled before start", initialFetchesStarted, initialFetchesCancelled)

	// If all were cancelled before starting, we can exit early
	if initialFetchesStarted == 0 && initialFetchesCancelled > 0 {
		cancelDownload() // Ensure progress goroutine stops
		<-progressDone   // Wait for progress to finish
		return fmt.Errorf("download cancelled before any chunks started fetching")
	}


	// Main download loop: manage chunk completion and errors
	activeChunks := initialFetchesStarted
	for activeChunks > 0 {
		select {
		case id := <-s.done:
			activeChunks-- // A chunk goroutine finished
			if s.chunks[id].length > 0 { // Error occurred, restart chunk
				// Check context before restarting
				select {
				case <-s.ctx.Done():
					s.log <- fmt.Sprintf("Chunk %d finished with error, but download cancelled. Not restarting.", id)
					continue // Don't restart if context is cancelled
				default:
				}

				s.log <- fmt.Sprintf("Chunk %d error, restarting", id)
				s.chunks[id].circuit = seq // Assign new circuit ID
				seq++
				client, req := s.chunkInit(id)
				go s.chunkFetch(id, client, req)
				activeChunks++ // Increment active count as we restarted one
			} else { // Chunk completed successfully
				s.log <- fmt.Sprintf("Chunk %d completed successfully", id)
				// Check if all chunks are done
				allDone := true
				s.rwmutex.RLock()
				// Check length AND cancel func status to see if chunk is truly done or just errored out previously
				for i := 0; i < s.circuits; i++ {
					if s.chunks[i].length > 0 && s.chunks[i].cancel != nil {
						allDone = false
						break
					}
				}
				s.rwmutex.RUnlock()

				if allDone {
					s.printPermanent("Download complete")
					cancelDownload() // Signal progress goroutine to stop
					<-progressDone   // Wait for progress goroutine
					// Drain any remaining messages from done channel if needed
					go func() {
						for range s.done {
						}
					}() // Drain in separate goroutine
					return nil // Successful completion
				}

				// Steal work if needed and possible
				longest := -1
				maxLength := int64(0)
				s.rwmutex.RLock()
				for i := 0; i < s.circuits; i++ {
					// Only consider chunks that are still active (have a cancel func) and have significant work left
					if s.chunks[i].cancel != nil && s.chunks[i].length > maxLength {
						longest = i
						maxLength = s.chunks[i].length
					}
				}
				s.rwmutex.RUnlock()

				// Only steal if the longest chunk is significantly large and the current chunk is idle
				if longest != -1 && maxLength > 5*torBlock && s.chunks[id].length == 0 {
					// Check context before stealing work
					select {
					case <-s.ctx.Done():
						s.log <- fmt.Sprintf("Chunk %d finished, but download cancelled. Not stealing work.", id)
						continue
					default:
					}

					s.log <- fmt.Sprintf("Chunk %d finished, stealing work from chunk %d", id, longest)
					s.rwmutex.Lock()
					// Steal roughly half of the remaining work
					stealAmount := s.chunks[longest].length / 2
					if stealAmount > 0 {
						s.chunks[id].length = stealAmount
						s.chunks[longest].length -= stealAmount
						s.chunks[id].start = s.chunks[longest].start + s.chunks[longest].length
						s.rwmutex.Unlock()

						// Restart the current chunk (id) with the stolen work
						client, req := s.chunkInit(id)
						go s.chunkFetch(id, client, req)
						activeChunks++ // Increment active count
					} else {
						s.rwmutex.Unlock() // Unlock if no work was actually stolen
						s.log <- fmt.Sprintf("Chunk %d finished, but longest chunk %d has too little work to steal.", id, longest)
					}
				} else if s.chunks[id].length == 0 {
					s.log <- fmt.Sprintf("Chunk %d finished, no suitable work to steal.", id)
				}
			}
		case <-time.After(time.Second * 30):
			// Check context before running darwin
			select {
			case <-s.ctx.Done():
				s.log <- "Download cancelled, skipping Darwin check."
				continue // Skip Darwin if context is cancelled
			default:
			}
			s.darwin() // Kill slow circuits
		case <-s.ctx.Done():
			s.printPermanent("Download cancelled by user.")
			// Drain done channel to allow goroutines to exit
			go func() {
				for range s.done {
					// Consume messages
				}
			}()
			<-progressDone // Wait for progress goroutine
			return fmt.Errorf("download cancelled")
		}
	}

	// Fallback in case loop exits unexpectedly
	cancelDownload()
	<-progressDone
	s.printPermanent("Download finished or cancelled.")
	// Check final state
	allDoneFinal := true
	s.rwmutex.RLock()
	for i := 0; i < s.circuits; i++ {
		// Check length AND if the chunk was ever active (cancel != nil)
		// A chunk might have length > 0 if it errored early and was never restarted due to cancellation
		if s.chunks[i].length > 0 && s.chunks[i].cancel != nil {
			allDoneFinal = false
			s.log <- fmt.Sprintf("Chunk %d did not complete fully (length: %d)", i, s.chunks[i].length)
			break
		}
	}
	s.rwmutex.RUnlock()
	if !allDoneFinal {
		return fmt.Errorf("download loop exited but not all active chunks finished")
	}
	return nil
}

// extractLinks finds all href attributes in anchor tags within an HTML node.
func extractLinks(n *html.Node, baseURL *url.URL) []*url.URL {
	var links []*url.URL
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" {
				// Attempt to parse the href relative to the base URL
				resolvedURL, err := baseURL.Parse(a.Val)
				if err == nil {
					// Basic filtering: ignore fragments and obviously weird schemes
					if resolvedURL.Scheme == "http" || resolvedURL.Scheme == "https" {
						// Further filter: ensure it's within the same host or a subpath
						// (This is a simple check, could be more robust)
						if resolvedURL.Host == baseURL.Host && strings.HasPrefix(resolvedURL.Path, baseURL.Path) {
							// Avoid adding the base URL itself if it's listed
							if resolvedURL.String() != baseURL.String() {
								links = append(links, resolvedURL)
							}
						} else if resolvedURL.Host == baseURL.Host && baseURL.Path == "/" && resolvedURL.Path != "/" {
							// Handle case where base URL is root "/"
							links = append(links, resolvedURL)
						}
						// Allow downloading from same host even if path is different? Maybe add flag later.
					}
				} else {
					// Log parsing errors if verbose?
					// fmt.Fprintf(os.Stderr, "Could not parse href '%s': %v\n", a.Val, err)
				}
				break // Found href, no need to check other attributes
			}
		}
	}
	// Recursively check child nodes
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		links = append(links, extractLinks(c, baseURL)...)
	}
	return links
}

// handleURL checks if a URL points to a directory listing or a file,
// and either recursively downloads the directory contents or downloads the single file.
func (s *State) handleURL(targetURL *url.URL, localBasePath string) error {
	s.printPermanent(fmt.Sprintf("Checking: %s", targetURL.String()))

	// Use a temporary client for checking content type
	client := httpClient("torget_check", s.userAgent)
	req, err := http.NewRequestWithContext(s.ctx, "GET", targetURL.String(), nil) // Use GET to fetch content
	if err != nil {
		return fmt.Errorf("failed to create check request for %s: %w", targetURL.String(), err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("check request failed for %s: %w", targetURL.String(), err)
	}
	defer resp.Body.Close() // Ensure body is closed

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("check request for %s returned non-success status: %d %s", targetURL.String(), resp.StatusCode, resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(contentType, "text/html")
	isDir := strings.HasSuffix(targetURL.Path, "/") // Assume trailing slash means directory

	// Treat as directory if Content-Type is HTML or URL ends with /
	if isHTML || isDir {
		s.printPermanent(fmt.Sprintf("Detected directory: %s", targetURL.String()))

		// Need to re-read the body as it was consumed by the check
		// Make a new request to get the body again
		reqBody, err := http.NewRequestWithContext(s.ctx, "GET", targetURL.String(), nil)
		if err != nil {
			return fmt.Errorf("failed to create body request for %s: %w", targetURL.String(), err)
		}
		respBody, err := client.Do(reqBody)
		if err != nil {
			return fmt.Errorf("body request failed for %s: %w", targetURL.String(), err)
		}
		defer respBody.Body.Close()
		if respBody.StatusCode < 200 || respBody.StatusCode >= 300 {
			return fmt.Errorf("body request for %s returned non-success status: %d %s", targetURL.String(), respBody.StatusCode, respBody.Status)
		}


		doc, err := html.Parse(respBody.Body)
		if err != nil {
			return fmt.Errorf("failed to parse HTML from %s: %w", targetURL.String(), err)
		}

		links := extractLinks(doc, targetURL)
		s.printPermanent(fmt.Sprintf("Found %d potential links in %s", len(links), targetURL.String()))

		for _, linkURL := range links {
			// Determine local path relative to the base path
			// We want the part of the link's path relative to the targetURL's path
			relPath, err := filepath.Rel(targetURL.Path, linkURL.Path)
			if err != nil {
				// Fallback if Rel fails (e.g., different roots) - just use the link's path basename?
				s.log <- fmt.Sprintf("Could not determine relative path for %s from %s: %v. Using basename.", linkURL.Path, targetURL.Path, err)
				relPath = filepath.Base(linkURL.Path)
			}
			// Clean the relative path
			relPath = filepath.Clean(relPath)
			// Ensure it's not trying to go above the base path (security)
			if strings.HasPrefix(relPath, "..") {
				s.log <- fmt.Sprintf("Skipping link outside base directory: %s", linkURL.String())
				continue
			}

			localPath := filepath.Join(localBasePath, relPath)

			// Check if the link itself likely points to a directory (ends with /)
			if strings.HasSuffix(linkURL.Path, "/") {
				// Create the directory locally
				err := os.MkdirAll(localPath, 0755)
				if err != nil {
					s.log <- fmt.Sprintf("Failed to create local directory %s: %v", localPath, err)
					continue // Skip this subdirectory if creation fails
				}
				// Recursively handle the subdirectory
				err = s.handleURL(linkURL, localPath)
				if err != nil {
					s.log <- fmt.Sprintf("Error processing subdirectory %s: %v", linkURL.String(), err)
					// Decide whether to continue or return error - for now, log and continue
				}
			} else {
				// Assume it's a file, attempt to download
				err := s.downloadFileInternal(linkURL, localPath)
				if err != nil {
					s.log <- fmt.Sprintf("Error downloading file %s: %v", linkURL.String(), err)
					// Log and continue with other files/dirs
				}
			}
			// Check for context cancellation between items
			select {
			case <-s.ctx.Done():
				s.printPermanent("Recursive download cancelled.")
				return s.ctx.Err() // Return context error
			default:
				// Continue processing next link
			}
		}
		return nil // Finished processing directory

	} else {
		// Not HTML or directory-like URL, assume it's a single file
		s.printPermanent(fmt.Sprintf("Treating as single file: %s", targetURL.String()))
		// Determine local path - should just be the base path provided
		return s.downloadFileInternal(targetURL, localBasePath)
	}
}


// Fetch is the main entry point.
func (s *State) Fetch(src string) int {
	srcUrl, err := url.Parse(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL '%s': %s\n", src, err.Error())
		return 1
	}

	// Determine base local path for downloads
	// If URL path ends in /, use the last path segment as the directory name
	// Otherwise, use the filename as the destination file.
	var initialLocalPath string
	urlPath := srcUrl.Path
	if strings.HasSuffix(urlPath, "/") {
		// It's a directory URL, create a local directory based on the last segment
		trimmedPath := strings.TrimSuffix(urlPath, "/")
		if trimmedPath == "" {
			// If it's just the root "/", use the hostname
			initialLocalPath = srcUrl.Hostname()
			if initialLocalPath == "" {
				initialLocalPath = "downloaded_site" // Default if no hostname
			}
		} else {
			initialLocalPath = filepath.Base(trimmedPath)
		}
		// Ensure the base directory exists
		if err := os.MkdirAll(initialLocalPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating base directory '%s': %v\n", initialLocalPath, err)
			return 1
		}
		fmt.Println("Target is a directory. Base download path:", initialLocalPath)
	} else {
		// It's likely a file URL, use the filename directly
		if urlPath == "" {
			initialLocalPath = "index" // Default if path is empty
		} else {
			initialLocalPath = filepath.Base(urlPath)
		}
		if initialLocalPath == "" || initialLocalPath == "." || initialLocalPath == "/" {
			initialLocalPath = "index" // Sanity check default
		}
		fmt.Println("Target is a file. Destination:", initialLocalPath)
	}


	// Start the process by handling the initial URL
	err = s.handleURL(srcUrl, initialLocalPath)
	if err != nil {
		// Check if it was a cancellation error
		if err == context.Canceled || err == context.DeadlineExceeded {
			s.printPermanent(fmt.Sprintf("Operation cancelled: %s", err.Error()))
		} else {
			s.printPermanent(fmt.Sprintf("Error: %s", err.Error()))
		}
		return 1
	}

	s.printPermanent("Processing complete.")
	return 0 // Success
}


func main() {
	circuits := flag.Int("circuits", 20, "concurrent circuits")
	minLifetime := flag.Int("min-lifetime", 10, "minimum circuit lifetime (seconds)")
	verbose := flag.Bool("verbose", false, "diagnostic details")
	userAgent := flag.String("user-agent", "", "Custom User-Agent string for HTTP requests (default: Go HTTP client)") // Added user-agent flag
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "torget 2.0, a fast large file downloader over locally installed Tor")
		fmt.Fprintln(os.Stderr, "Copyright © 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>")
		fmt.Fprintln(os.Stderr, "Licensed under GNU/GPL version 3")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: torget [FLAGS] URL")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	ctx := context.Background()
	// Pass userAgent flag value to NewState
	state := NewState(ctx, *circuits, *minLifetime, *verbose, *userAgent)
	context.Background()
	os.Exit(state.Fetch(flag.Arg(0)))
}

// vim: noet:ts=4:sw=4:sts=4:spell
