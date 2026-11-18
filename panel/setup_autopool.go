package main

// A second foreign server on a port one tunnel already serves.
//
// A port belongs to one tunnel until a cluster pool covers it, so Setup used
// to refuse the second server and the user had to know the order: make the
// pool first, add the other server after. With "pool_on_clash" the panel does
// that order itself: it makes a failover pool on the port with the tunnel that
// has it, and the new server joins the pool as soon as it exists (lbAutoJoin).

import (
	"fmt"
	"sort"
	"time"
)

// autoPoolForClash makes a failover pool for each of ports that one or more
// tunnels serve and no pool covers. It returns the pools it made (so the
// caller can undo them). Nothing is made without the cluster license, and a
// port another of Hashem's configs holds is left for the normal "already
// served" answer.
func autoPoolForClash(ports []int) ([]LBPool, error) {
	if !isClusterLicensed() || len(ports) == 0 {
		return nil, nil
	}
	cfg := loadClusterConfig()
	pooled := map[int]bool{}
	for _, p := range cfg.Pools {
		pooled[p.Port] = true
	}
	links := lbLinksFrom(lbSnapshot())
	var made []LBPool
	for _, port := range ports {
		if pooled[port] {
			continue
		}
		var owners []lbLink
		for _, l := range links {
			if hasInt(l.Ports, port) {
				owners = append(owners, l)
			}
		}
		if len(owners) == 0 {
			continue
		}
		// FRP forwards UDP with every port; a Backhaul tunnel only when it was
		// set up to, so a pool with Backhaul in it starts as TCP.
		proto := "both"
		for _, l := range owners {
			if l.Engine != "frp" {
				proto = "tcp"
			}
		}
		p := LBPool{Port: port, Proto: proto, Mode: lbFailover}
		for i, l := range owners {
			p.Members = append(p.Members, LBMember{Link: l.ID, Remote: l.Remote, Weight: 1, Priority: i})
		}
		made = append(made, p)
	}
	if len(made) == 0 {
		return nil, nil
	}
	var bad error
	_, err := updateClusterConfig(func(c *ClusterConfig) error {
		for _, p := range made {
			if code, msg := validatePool(*c, p, -1); code != "" {
				bad = fmt.Errorf("cannot make a pool on port %d: %s", p.Port, msg)
				return bad
			}
			c.Pools = append(c.Pools, p)
			clusterEventf("info", "%s created (mode %s, %d members): a second foreign server was added on port %d.", poolLabel(p), p.Mode, len(p.Members), p.Port)
		}
		sort.Slice(c.Pools, func(i, j int) bool { return c.Pools[i].Port < c.Pools[j].Port })
		return nil
	})
	if bad != nil {
		return nil, bad
	}
	if err != nil {
		return nil, err
	}
	return made, nil
}

// undoAutoPools removes the pools autoPoolForClash made, when the tunnel they
// were made for could not be created.
func undoAutoPools(made []LBPool) {
	if len(made) == 0 {
		return
	}
	_, _ = updateClusterConfig(func(c *ClusterConfig) error {
		out := c.Pools[:0]
		for _, p := range c.Pools {
			drop := false
			for _, m := range made {
				if m.Port == p.Port && m.Proto == p.Proto {
					drop = true
				}
			}
			if !drop {
				out = append(out, p)
			}
		}
		c.Pools = out
		return nil
	})
}

// autoPoolWait is how long a new pool may take to move its members' relays
// behind their private addresses (the cluster monitor does it on its next
// tick, and restarts each relay). The new tunnel's relay is made on its private
// address at once, and could not listen on the port while the old relay still
// holds it on every address, so the installer waits for this.
var autoPoolWait = 45 * time.Second

// waitPoolsBound wakes the cluster monitor and waits until every member relay
// of the pools in made listens behind the pool.
func waitPoolsBound(made []LBPool) error {
	if len(made) == 0 {
		return nil
	}
	clusterWake()
	deadline := time.Now().Add(autoPoolWait)
	for {
		byID := map[int]lbLink{}
		for _, l := range lbLinksFrom(lbSnapshot()) {
			byID[l.ID] = l
		}
		pending := ""
		for _, p := range made {
			for _, m := range p.Members {
				if l, ok := byID[m.Link]; ok && !lbIsBound(l.Svc, l.Addr) {
					pending = lbLinkName(l)
				}
			}
		}
		if pending == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not move behind the new pool in %s", pending, autoPoolWait)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
