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
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// State represents the download state and configuration
type State struct {
	ctx                context.Context
	src                string
	dst                string
	bytesTotal         int64
	bytesPrev          int64
	circuits           int
	minLifetime        time.Duration
	verbose            bool
	userAgent          string
	chunks             []chunk
	done               chan int
	log                chan string
	terminal           bool
	rwmutex            sync.RWMutex
	recursive          bool
	whitelistFile      string        // Path to file containing whitelisted extensions
	whitelistExtensions map[string]bool // Map of allowed extensions for quick lookup
}

// NewState creates a new State instance with the given configuration
func NewState(ctx context.Context, circuits int, minLifetime int, verbose bool, userAgent string) *State {
	var s State
	s.circuits = circuits
	s.minLifetime = time.Duration(minLifetime) * time.Second
	s.userAgent = userAgent
	s.verbose = verbose
	s.recursive = false
	s.chunks = make([]chunk, s.circuits)
	s.ctx = ctx
	s.done = make(chan int)
	s.log = make(chan string, 10)
	st, _ := os.Stdout.Stat()
	s.terminal = st.Mode()&os.ModeCharDevice == os.ModeCharDevice
	s.whitelistExtensions = make(map[string]bool)
	return &s
}

// LoadWhitelist loads and parses the whitelist file containing allowed file extensions
func (s *State) LoadWhitelist(whitelistFile string) error {
	if whitelistFile == "" {
		return nil // No whitelist file specified, allow all extensions
	}

	s.whitelistFile = whitelistFile
	s.whitelistExtensions = make(map[string]bool)

	file, err := os.Open(whitelistFile)
	if err != nil {
		return fmt.Errorf("failed to open whitelist file %s: %v", whitelistFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		
		// Remove comments (everything after #)
		if commentIdx := strings.Index(line, "#"); commentIdx >= 0 {
			line = line[:commentIdx]
		}
		
		// Trim whitespace and skip empty lines
		ext := strings.TrimSpace(line)
		if ext == "" {
			continue // Skip empty lines
		}

		// Ensure extension starts with a dot
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}

		// Convert to lowercase for case-insensitive matching
		ext = strings.ToLower(ext)
		s.whitelistExtensions[ext] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading whitelist file %s: %v", whitelistFile, err)
	}

	fmt.Printf("Loaded %d whitelisted extensions from %s\n", len(s.whitelistExtensions), whitelistFile)
	return nil
}

// IsExtensionAllowed checks if a file with the given path is allowed based on its extension
func (s *State) IsExtensionAllowed(filePath string) bool {
	// If no whitelist is specified, allow all files
	if s.whitelistFile == "" || len(s.whitelistExtensions) == 0 {
		return true
	}

	// Get the file extension and convert to lowercase
	ext := strings.ToLower(filepath.Ext(filePath))
	return s.whitelistExtensions[ext]
}

// printPermanent prints a permanent message to the terminal
func (s *State) printPermanent(txt string) {
	if s.terminal {
		fmt.Printf("\r%-40s\n", txt)
	} else {
		fmt.Println(txt)
	}
}

// printTemporary prints a temporary message to the terminal
func (s *State) printTemporary(txt string) {
	if s.terminal {
		fmt.Printf("\r%-40s", txt)
	}
}

// getExitNode retrieves and logs the Tor exit node information
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

// printLogs prints all accumulated log messages
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

// ignoreLogs discards all accumulated log messages
func (s *State) ignoreLogs() {
	for len(s.log) > 0 {
		<-s.log
	}
}

// statusLine generates a status line for the current download progress
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

// progress continuously updates the download progress
func (s *State) progress() {
	for {
		time.Sleep(time.Second)
		if s.verbose {
			s.printLogs()
		} else {
			s.ignoreLogs()
		}
		s.printTemporary(s.statusLine())
	}
}

// darwin kills the worst performing circuit
func (s *State) darwin() {
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
		s.chunks[victim].cancel()
		s.chunks[victim].cancel = nil
	}
	s.rwmutex.RUnlock()
}
