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
	"os"
	"path/filepath"
	"time"
)

// Fetch downloads a single file from src to dst
func (s *State) Fetch(src string, dst string) int {
	s.src = src
	s.dst = dst // Use the provided destination path

	// Ensure the destination directory exists
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		fmt.Printf("Error creating directory %s: %v\n", dstDir, err)
		return 1
	}

	fmt.Println("Downloading:", s.src)
	fmt.Println("Output file:", s.dst)

	// get the target length
	// Pass userAgent to httpClient
	client := httpClient("torget", s.userAgent)
	// Use a GET request instead of HEAD to get the initial length, as some servers might handle HEAD incorrectly.
	getReq, err := http.NewRequest("GET", s.src, nil)
	if err != nil {
		fmt.Println("Failed to create initial GET request:", err.Error())
		return 1
	}
	resp, err := client.Do(getReq)
	if err != nil {
		fmt.Println("Initial GET request failed:", err.Error())
		return 1
	}
	// IMPORTANT: Close the body immediately after getting the length.
	// We don't want to download data here, just get the size.
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Initial GET request returned non-success status: %d %s\n", resp.StatusCode, resp.Status)
		// Attempt to read body for more details, might be helpful for debugging
		bodyBytes, _ := io.ReadAll(resp.Body)
		if len(bodyBytes) > 0 {
			fmt.Println("Response body:", string(bodyBytes))
		}
		return 1
	}

	if resp.ContentLength <= 0 {
		fmt.Println("Failed to retrieve download length (Content-Length <= 0)")
		return 1
	}
	s.bytesTotal = resp.ContentLength
	fmt.Println("Download length:", s.bytesTotal, "bytes")

	// create the output file
	file, err := os.Create(s.dst)
	if file != nil {
		file.Close()
	}
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	// initialize chunks
	chunkLen := s.bytesTotal / int64(s.circuits)
	seq := 0
	for id := 0; id < s.circuits; id++ {
		s.chunks[id].start = int64(id) * chunkLen
		s.chunks[id].length = chunkLen
		s.chunks[id].circuit = seq
		seq++
	}
	s.chunks[s.circuits-1].length += s.bytesTotal % int64(s.circuits)

	// spawn initial fetchers
	go s.progress()
	go func() {
		for id := 0; id < s.circuits; id++ {
			client, req := s.chunkInit(id)
			go s.chunkFetch(id, client, req)
			time.Sleep(499 * time.Millisecond) // be gentle to the local tor daemon
		}
	}()

	// spawn additional fetchers as needed
	for {
		select {
		case id := <-s.done:
			if s.chunks[id].length > 0 { // error
				// resume in a new and hopefully faster circuit
				s.chunks[id].circuit = seq
				seq++
			} else { // completed
				longest := 0
				s.rwmutex.RLock()
				for i := 1; i < s.circuits; i++ {
					if s.chunks[i].length > s.chunks[longest].length {
						longest = i
					}
				}
				s.rwmutex.RUnlock()
				if s.chunks[longest].length == 0 { // all done
					s.printPermanent("Download complete")
					return 0
				}
				if s.chunks[longest].length <= 5*torBlock { // too short to split
					continue
				}
				// this circuit is faster, so we split 80%/20%
				s.rwmutex.Lock()
				s.chunks[id].length = s.chunks[longest].length * 4 / 5
				s.chunks[longest].length -= s.chunks[id].length
				s.chunks[id].start = s.chunks[longest].start + s.chunks[longest].length
				s.rwmutex.Unlock()
			}
			client, req := s.chunkInit(id)
			go s.chunkFetch(id, client, req)
		case <-time.After(time.Second * 30):
			s.darwin()
		}
	}
}
