package newtonauth

import "net/url"

func httpNewRequest(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}
