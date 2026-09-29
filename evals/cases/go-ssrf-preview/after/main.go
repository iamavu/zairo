package main

import (
	"io"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"images.example.com": true, "cdn.example.com": true}

func PreviewURL(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(target.String())
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func main() {
	http.HandleFunc("/preview", PreviewURL)
	http.ListenAndServe(":8080", nil)
}
