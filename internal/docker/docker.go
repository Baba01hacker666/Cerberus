package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Container struct {
	ID       string            `json:"ID"`
	Names    string            `json:"Names"`
	Image    string            `json:"Image"`
	Labels   map[string]string `json:"-"`
	LabelRaw string            `json:"Labels"`
	State    string            `json:"State"`
	Ports    string            `json:"Ports"`
}

type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

func ParseLabels(raw string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return m
}

func LabelMatches(labels map[string]string, filter string) bool {
	if filter == "" {
		return true
	}
	normalized := strings.ReplaceAll(filter, " ", ",")
	for _, f := range strings.Split(normalized, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if k, v, hasEq := strings.Cut(f, "="); hasEq {
			if labels[strings.TrimSpace(k)] != strings.TrimSpace(v) {
				return false
			}
		} else {
			if _, ok := labels[f]; !ok {
				return false
			}
		}
	}
	return true
}

func ListContainers(socket, labelFilter string) ([]Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{"ps", "--format", "{{json .}}"}
	if labelFilter != "" {
		args = []string{"ps", "--filter", "label=" + labelFilter, "--format", "{{json .}}"}
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	if socket != "" {
		cmd.Env = append(cmd.Environ(), "DOCKER_HOST=unix://"+socket)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	return parseContainersOutput(string(out)), nil
}

func parseContainersOutput(raw string) []Container {
	var containers []Container
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c Container
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		c.Labels = ParseLabels(c.LabelRaw)
		containers = append(containers, c)
	}
	return containers
}

// WatchEvents streams docker events until ctx cancels.
func WatchEvents(ctx context.Context, socket string, onEvent func(Event)) error {
	args := []string{"events", "--filter", "type=container", "--format", "{{json .}}"}
	cmd := exec.CommandContext(ctx, "docker", args...)
	if socket != "" {
		cmd.Env = append(cmd.Environ(), "DOCKER_HOST=unix://"+socket)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		onEvent(e)
	}
	return cmd.Wait()
}

func InspectContainer(socket, id string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "inspect", id)
	if socket != "" {
		cmd.Env = append(cmd.Environ(), "DOCKER_HOST=unix://"+socket)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(out, &arr); err != nil {
		return nil, err
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("container %s not found", id)
	}
	return arr[0], nil
}

func ContainerIP(socket, id, network string) (string, error) {
	info, err := InspectContainer(socket, id)
	if err != nil {
		return "", err
	}
	nw, _ := info["NetworkSettings"].(map[string]interface{})
	nets, _ := nw["Networks"].(map[string]interface{})
	if network != "" {
		if n, ok := nets[network].(map[string]interface{}); ok {
			if ip, _ := n["IPAddress"].(string); ip != "" {
				return ip, nil
			}
		}
	}
	for _, n := range nets {
		if m, ok := n.(map[string]interface{}); ok {
			if ip, _ := m["IPAddress"].(string); ip != "" {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("container %s has no ip", id)
}

func Now() int64 { return time.Now().Unix() }

func ShortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
