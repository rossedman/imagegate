// Package docker is a minimal dockerd API client for the two inspect calls
// imagegate needs. Those calls pass back through imagegate as GETs and are
// always allowed.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrNotFound is returned when dockerd answers 404.
var ErrNotFound = errors.New("not found")

// Image is the subset of GET /images/{name}/json that imagegate uses.
type Image struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	RepoDigests  []string `json:"RepoDigests"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Variant      string   `json:"Variant"`
}

// Container is the subset of GET /containers/{id}/json that imagegate uses.
type Container struct {
	ID string `json:"Id"`
	// Image is the image ID the container was created from.
	Image  string `json:"Image"`
	Config struct {
		// Image is the reference the container was created with.
		Image string `json:"Image"`
	} `json:"Config"`
}

// Client talks to dockerd over its Unix socket.
type Client struct {
	http *http.Client
}

// New returns a client for the dockerd socket at socket.
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    16,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
}

// InspectImage resolves a reference or image ID the same way dockerd will
// when it handles the create.
func (c *Client) InspectImage(ctx context.Context, ref string) (*Image, error) {
	var img Image
	if err := c.get(ctx, "/images/"+ref+"/json", &img); err != nil {
		return nil, err
	}
	return &img, nil
}

// InspectContainer returns the container's image ID and creation reference.
func (c *Client) InspectContainer(ctx context.Context, id string) (*Container, error) {
	var ct Container
	if err := c.get(ctx, "/containers/"+id+"/json", &ct); err != nil {
		return nil, err
	}
	return &ct, nil
}

// get decodes a 200 JSON response from path into out. 404 is ErrNotFound;
// other statuses are errors carrying a bounded slice of the body.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dockerd: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection is reused
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("dockerd: GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
