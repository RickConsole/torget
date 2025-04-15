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
	"net/url"
	"os"
	"path/filepath"
)

func main() {
	circuits := flag.Int("circuits", 20, "concurrent circuits")
	minLifetime := flag.Int("min-lifetime", 10, "minimum circuit lifetime (seconds)")
	verbose := flag.Bool("verbose", false, "diagnostic details")
	recursive := flag.Bool("recursive", false, "recursively download from directory listing URL")
	userAgent := flag.String("user-agent", "", "Custom User-Agent string for HTTP requests (default: Go HTTP client)")
	whitelistFile := flag.String("whitelist-file", "", "Path to a file containing whitelisted extensions for recursive downloads (one per line)")
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
	state.recursive = *recursive // Set recursive state

	// Load whitelist file if specified and recursive mode is enabled
	if state.recursive && *whitelistFile != "" {
		if err := state.LoadWhitelist(*whitelistFile); err != nil {
			fmt.Println("Error loading whitelist file:", err)
			os.Exit(1)
		}
	}

	srcURL := flag.Arg(0)

	if state.recursive {
		// Call the recursive download function
		os.Exit(state.FetchRecursive(srcURL))
	} else {
		// Original behavior: derive destination from URL path
		parsedURL, err := url.Parse(srcURL)
		if err != nil {
			fmt.Println("Invalid URL:", err.Error())
			os.Exit(1)
		}
		path := parsedURL.EscapedPath()
		dstPath := filepath.Base(path)
		if dstPath == "." || dstPath == "/" || dstPath == "" {
			dstPath = "index" // Default filename if path ends in / or is empty
		}
		os.Exit(state.Fetch(srcURL, dstPath))
	}
}
