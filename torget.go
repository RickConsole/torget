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

// This file is kept for backward compatibility.
// The code has been reorganized into multiple files for better maintainability:
//
// - main.go: Entry point, CLI flags, and high-level program flow
// - client.go: HTTP client creation and custom transport
// - state.go: State struct definition and core state management
// - chunks.go: Chunk handling and circuit management
// - download.go: Single file download functionality
// - directory.go: Directory listing and recursive downloading
