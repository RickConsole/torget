# torget

## Updates

Needed a couple extra features for the tool so I decided to fork. 

Added:
- Custom User Agent
- Get's file info from a GET request rather than a HEAD request. This helps with certain sites who might behaive differently if you supply a HEAD. 

## Description

The tool downloads large files over a locally installed Tor client by
aggressively discovering a pool of fast circuits and using them in parallel.
With slow servers, this strategy bypasses per-IP traffic shaping, resulting in
much faster downloads.

Onion services are fully supported.

## Building From Source

    $ git clone https://github.com/mtrojnar/torget.git
    [...]
    $ cd torget
    $ go build torget.go

## Using

    $ ./torget -h
    torget 2.0, a fast large file downloader over locally installed Tor
    Copyright © 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
    Licensed under GNU/GPL version 3

    Usage: torget [FLAGS] URL
      -circuits int
            concurrent circuits (default 20)
      -min-lifetime int
            minimum circuit lifetime (seconds) (default 10)
      -verbose
            diagnostic details
    $ ./torget https://download.tails.net/tails/stable/tails-amd64-5.16.1/tails-amd64-5.16.1.img
    Output file: tails-amd64-5.16.1.img
    Download length: 1326448640 bytes
    Download complete
