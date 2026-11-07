---
title: Recover from a rejected sync
weight: 90
description: What to do when a full sync is refused because it would change access too much.
---

Before it replaces the live permissions, the server compares a new sync with them. A sync that removes, adds or raises more than the [limits]({{< relref "../reference/limits" >}}) allow is rejected, and `lfs.sync.failures` increases with reason `rejected`. The live permissions stay in force.

A real reorganisation, such as a mass offboarding, can trip the limits. If nobody acts, the permissions age past `NARAEN_SNAPSHOT_MAX_AGE` and the server refuses every request.

## Decide whether the change is real

Read the server's log for the rejected sync. If the change is a provider bug or a partial GitHub outage, wait: the next sync will usually succeed with sensible numbers.

## Accept a change that is real

Once you have reviewed the change and want it, restart the server. The first sync after a start has no baseline to compare against and is checked only for being non-empty, so it is accepted.

An empty snapshot is never accepted.

## Avoid the problem

Make large changes in steps across several sync intervals, each under the limits.
