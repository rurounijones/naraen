---
title: naraen
description: A self-hosted Git LFS server that keeps code on GitHub and stores large files in Amazon S3.
---

{{% blocks/cover title="naraen" image_anchor="top" height="auto" %}}
A self-hosted Git LFS server. Code stays on GitHub; large files go to Amazon S3.

[Get started]({{< relref "/docs/tutorials" >}}) or [read the docs]({{< relref "/docs" >}}).
{{% /blocks/cover %}}

{{% blocks/lead color="primary" %}}
Developers sign in with the SSH keys they already use for GitHub. GitHub decides what they may access. File bytes travel directly between the client and S3, so the server only handles small control requests.
{{% /blocks/lead %}}

{{% blocks/section color="white" type="row" %}}
{{% blocks/feature icon="fa-key" title="No new credentials" %}}
A developer's GitHub SSH key is their identity. CI jobs exchange a GitHub Actions OIDC token for a read-only token, with no stored secret.
{{% /blocks/feature %}}
{{% blocks/feature icon="fa-lock" title="Fails closed" %}}
Every decision is a lookup in one in-memory snapshot of GitHub's permissions. Anything not in it is denied, and a stale snapshot refuses all requests.
{{% /blocks/feature %}}
{{% blocks/feature icon="fa-chart-line" title="Audited" %}}
An audit record for every sign-in, refusal and token, plus OpenTelemetry metrics, traces and logs for each request.
{{% /blocks/feature %}}
{{% /blocks/section %}}
