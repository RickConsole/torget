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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// processDirectory fetches and parses a directory listing, downloading files and recursing into subdirs.
func (s *State) processDirectory(dirURL string, localBaseDir string) error {
	fmt.Println("Processing directory:", dirURL, "->", localBaseDir)

	parsedURL, err := url.Parse(dirURL)
	if err != nil {
		return fmt.Errorf("invalid directory URL %s: %v", dirURL, err)
	}

	// Use a unique client for directory listing checks
	client := httpClient("torget-dir", s.userAgent) // Maybe reuse client? For now, new one per dir.
	req, err := http.NewRequest("GET", dirURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %v", dirURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to GET %s: %v", dirURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Attempt to read body for more details
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := ""
		if len(bodyBytes) > 0 {
			bodyStr = fmt.Sprintf(" Body: %s", string(bodyBytes))
		}
		return fmt.Errorf("GET request to %s returned non-success status: %d %s.%s", dirURL, resp.StatusCode, resp.Status, bodyStr)
	}

	// Ensure it's HTML before parsing
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		return fmt.Errorf("URL %s is not HTML (%s), cannot process as directory", dirURL, contentType)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse HTML from %s: %v", dirURL, err)
	}

	var wg sync.WaitGroup // Wait group for concurrent file downloads within this directory level
	var fileQueue = make(chan struct { url string; path string }, s.circuits) // Buffered channel for files
	var errors = make(chan error, s.circuits+1) // Channel for errors from goroutines

	// Start worker goroutines to download files from the queue
	for i := 0; i < s.circuits; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range fileQueue {
				fmt.Printf("Worker starting download: %s -> %s\n", item.url, item.path)
				// Create a new state for each file download to avoid race conditions on shared fields like chunks, bytesTotal etc.
				// This is a simplification; a more robust solution might share the client pool but manage state per file.
				fileState := NewState(s.ctx, s.circuits, int(s.minLifetime.Seconds()), s.verbose, s.userAgent)
				// We need to reset progress reporting for each file. The current global progress won't work well.
				// For simplicity, let's skip the detailed progress bar for recursive downloads for now.
				// go fileState.progress() // This would need significant rework for multiple files.
				exitCode := fileState.Fetch(item.url, item.path)
				if exitCode != 0 {
					errors <- fmt.Errorf("failed to download %s (exit code %d)", item.url, exitCode)
				} else {
					fmt.Printf("Worker finished download: %s\n", item.path)
				}
			}
		}()
	}

	var parseHTML func(*html.Node)
	parseHTML = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					link := a.Val
					// Basic filtering
					if link == "" || link == "../" || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "?") || strings.Contains(link, ":") && !strings.HasPrefix(link, "http") { // Avoid mailto:, etc. but allow http(s)
						continue
					}

					// Resolve the link relative to the current directory URL
					resolvedURL, err := parsedURL.Parse(link)
					if err != nil {
						fmt.Printf("Skipping invalid link '%s' in %s: %v\n", link, dirURL, err)
						continue
					}
					absoluteURL := resolvedURL.String()

					// Basic check to stay within the same host/path prefix
					// This prevents following links to completely different sites or parent directories
					if !strings.HasPrefix(absoluteURL, dirURL) {
						// Allow links relative to the *directory* path, not just the full base URL if it included a filename
						currentDirPrefix := dirURL
						if !strings.HasSuffix(currentDirPrefix, "/") {
							// This logic might be tricky if dirURL itself has query params etc.
							// A more robust check might compare host and path prefixes.
							currentDirPrefix = filepath.Dir(currentDirPrefix) + "/"
						}
						// A simpler check: ensure it starts with the original base URL's scheme+host+path prefix
						// This needs the original base URL passed down or stored in State. Let's assume dirURL is sufficient for now.
						// For now, a simple prefix check on the current dirURL is a basic safeguard.
						if !strings.HasPrefix(absoluteURL, currentDirPrefix) {
							fmt.Printf("Skipping external or unrelated link: %s (relative to %s)\n", absoluteURL, currentDirPrefix)
							continue
						}
					}

					// Determine local path component from the link itself
					linkPathPart := resolvedURL.Path
					// If the original URL had a path, remove that prefix from the link's path
					if parsedURL.Path != "" && parsedURL.Path != "/" {
						linkPathPart = strings.TrimPrefix(linkPathPart, parsedURL.Path)
					}
					linkPathPart = strings.TrimPrefix(linkPathPart, "/") // Ensure it's relative

					if linkPathPart == "" { // Skip links pointing back to the directory index itself
						continue
					}

					localPath := filepath.Join(localBaseDir, linkPathPart)

					// Check if it's a directory
					if strings.HasSuffix(link, "/") {
						fmt.Printf("Found directory link: %s -> Local: %s\n", absoluteURL, localPath)
						// Create local directory
						if err := os.MkdirAll(localPath, 0755); err != nil {
							errors <- fmt.Errorf("error creating directory %s: %v", localPath, err)
							continue // Skip this directory
						}
						// Recursively process the subdirectory
						// Run this sequentially for now to avoid overwhelming Tor/network with directory fetches
						err := s.processDirectory(absoluteURL, localPath)
						if err != nil {
							errors <- fmt.Errorf("error processing subdirectory %s: %v", absoluteURL, err)
						}
					} else {
						// Check if the file extension is allowed based on the whitelist
						if !s.IsExtensionAllowed(localPath) {
							fmt.Printf("Skipping file with non-whitelisted extension: %s\n", localPath)
							continue
						}

						fmt.Printf("Found file link: %s -> Local: %s\n", absoluteURL, localPath)
						// Ensure parent directory exists before queueing
						parentDir := filepath.Dir(localPath)
						if err := os.MkdirAll(parentDir, 0755); err != nil {
							errors <- fmt.Errorf("error creating parent directory %s for file %s: %v", parentDir, localPath, err)
							continue // Skip this file
						}
						// Add to the download queue
						fileQueue <- struct { url string; path string }{absoluteURL, localPath}
					}
					break // Found href
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			parseHTML(c)
		}
	}

	// Start parsing
	parseHTML(doc)

	// Close the file queue to signal workers there are no more files for *this* directory level
	close(fileQueue)

	// Wait for all file download workers for this level to complete
	wg.Wait()

	// Check for errors accumulated during this directory processing
	close(errors) // Close error channel after WaitGroup finishes
	finalErr := ""
	for err := range errors {
		finalErr += err.Error() + "\n"
	}

	if finalErr != "" {
		return fmt.Errorf("errors occurred processing directory %s:\n%s", dirURL, finalErr)
	}

	fmt.Println("Finished processing directory:", dirURL)
	return nil // Success for this directory
}

// FetchRecursive handles the initial setup for recursive download
func (s *State) FetchRecursive(baseURL string) int {
	fmt.Println("Starting recursive download from:", baseURL)

	// Determine the base local directory name from the URL path
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Printf("Invalid base URL %s: %v\n", baseURL, err)
		return 1
	}
	baseDir := filepath.Base(parsedBaseURL.Path)
	if baseDir == "." || baseDir == "/" || baseDir == "" {
		// Use host as base dir if path is trivial, sanitize it
		baseDir = strings.ReplaceAll(parsedBaseURL.Host, ":", "_") // Basic sanitization
	}
	fmt.Println("Using base output directory:", baseDir)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		fmt.Printf("Error creating base directory %s: %v\n", baseDir, err)
		return 1
	}

	// Initial check: Is the base URL itself a directory listing or a single file?
	client := httpClient("torget-init", s.userAgent)
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		fmt.Printf("Failed to create initial request for %s: %v\n", baseURL, err)
		return 1
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Initial GET failed for %s: %v\n", baseURL, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("Initial GET for %s returned status %d %s. Body: %s\n", baseURL, resp.StatusCode, resp.Status, string(bodyBytes))
		// Decide whether to proceed as single file? Let's error out for now.
		return 1
	}

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.HasPrefix(contentType, "text/html")
	// Close the initial response body *now* if it's HTML, as processDirectory will fetch it again.
	// If it's not HTML, Fetch will handle the body.
	if isHTML {
		resp.Body.Close() // Important: close body before calling processDirectory
		err = s.processDirectory(baseURL, baseDir)
		if err != nil {
			fmt.Printf("Recursive download failed: %v\n", err)
			return 1 // Indicate failure
		}
		fmt.Println("Recursive download process completed.")
		return 0 // Indicate success
	} else {
		// Not HTML, treat as single file download into the base directory
		fmt.Printf("URL %s is not HTML (%s), attempting single file download into %s/.\n", baseURL, contentType, baseDir)
		// Determine filename
		dstPath := filepath.Join(baseDir, filepath.Base(parsedBaseURL.Path))
		if filepath.Base(parsedBaseURL.Path) == "." || filepath.Base(parsedBaseURL.Path) == "/" || filepath.Base(parsedBaseURL.Path) == "" {
			dstPath = filepath.Join(baseDir, "index") // Default filename if path is trivial
		}
		
		// Check if the file extension is allowed based on the whitelist
		if !s.IsExtensionAllowed(dstPath) {
			fmt.Printf("Skipping file with non-whitelisted extension: %s\n", dstPath)
			return 0 // Skip but don't treat as error
		}
		
		// Call the original Fetch for the single file
		return s.Fetch(baseURL, dstPath)
	}
}
