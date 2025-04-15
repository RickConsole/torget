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
	"net/http"
	"net/url"
)

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

// httpClient creates a new HTTP client with Tor proxy and custom User-Agent
func httpClient(user string, ua string) *http.Client {
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
