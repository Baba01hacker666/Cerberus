package docker

import "testing"

func TestParseLabelsAndMatching(t *testing.T) {
	raw := `{"ID":"abcdef0123456789","Names":"web-1","Image":"nginx:alpine","Labels":"cerberus.enable=true,cerberus.isolate=false,env=prod","State":"running"}`
	containers := parseContainersOutput(raw + "\n")
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	c := containers[0]
	if ShortID(c.ID) != "abcdef012345" {
		t.Fatalf("unexpected ShortID: %s", ShortID(c.ID))
	}
	if !LabelMatches(c.Labels, "cerberus.enable=true,env=prod") {
		t.Fatalf("expected label filter match")
	}
	if LabelMatches(c.Labels, "cerberus.enable=true,env=staging") {
		t.Fatalf("expected label filter mismatch")
	}
}
