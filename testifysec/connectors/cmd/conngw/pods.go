package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// podStatus reads the gateway's own pod from the API server: the image each plugin container runs,
// as the node reports it. The pod spec's image can be changed on a running pod, so this is read for
// every stream, not once.
type podStatus struct {
	url       string // .../api/v1/namespaces/<ns>/pods/<name>
	client    *http.Client
	tokenFile string
}

// podName is a pod name (an RFC 1123 subdomain).
var podName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// podURL is the API path of the gateway's own pod, from the Downward API's metadata.name and
// metadata.namespace in POD_NAME and POD_NAMESPACE. The hostname is not the pod's name when the pod
// sets spec.hostname or setHostnameAsFQDN.
func podURL(getenv func(string) string) (string, error) {
	name, ns := getenv("POD_NAME"), getenv("POD_NAMESPACE")
	if !podName.MatchString(name) || !dnsLabel.MatchString(ns) {
		return "", errors.New("POD_NAME and POD_NAMESPACE must name this pod (Downward API metadata.name, metadata.namespace)")
	}
	return "https://kubernetes.default.svc/api/v1/namespaces/" + ns + "/pods/" + name, nil
}

// container is one container instance as the pod's status reports it.
type container struct {
	id string // "<runtime>://<hex>"
}

// check returns the container's instance when it is running the image whose digest is given, else
// an error.
func (p *podStatus) check(ctx context.Context, name, digest string) (container, error) {
	token, err := os.ReadFile(p.tokenFile)
	if err != nil {
		return container{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return container{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	// The API server answers at the fixed URL or not at all: a redirect is refused, never followed,
	// so the bearer token goes nowhere else (and never over plain HTTP).
	client := *p.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return container{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return container{}, fmt.Errorf("pod status: HTTP %d", resp.StatusCode)
	}
	var pod struct {
		Status struct {
			ContainerStatuses []struct {
				Name        string `json:"name"`
				ContainerID string `json:"containerID"`
				ImageID     string `json:"imageID"`
				State       struct {
					Running *struct{} `json:"running"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pod); err != nil {
		return container{}, fmt.Errorf("pod status: %w", err)
	}
	for _, c := range pod.Status.ContainerStatuses {
		if c.Name != name {
			continue
		}
		got, err := imageDigestOf(c.ImageID)
		if err != nil || c.State.Running == nil || c.ContainerID == "" || got != digest {
			return container{}, fmt.Errorf("container %s is not running the image the profile pins", name)
		}
		return container{id: c.ContainerID}, nil
	}
	return container{}, errors.New("container " + name + " is not in this pod")
}

// imageDigestOf is the digest in a container status's imageID: an optional containerd:// or
// docker:// runtime prefix, then "<repository>@sha256:<hex>" or the bare digest. Any other scheme,
// or a second one, is an error: the gateway does not guess at a format it has not been shown.
func imageDigestOf(imageID string) (string, error) {
	rest := imageID
	if scheme, after, ok := strings.Cut(imageID, "://"); ok {
		if scheme != "containerd" && scheme != "docker" {
			return "", fmt.Errorf("image ID %q has an unknown runtime scheme", imageID)
		}
		rest = after
	}
	if strings.Contains(rest, "://") {
		return "", fmt.Errorf("image ID %q has more than one scheme", imageID)
	}
	if _, d, ok := strings.Cut(rest, "@"); ok {
		return d, nil
	}
	return rest, nil
}
