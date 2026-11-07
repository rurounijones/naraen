---
title: Connect a repository to the server
weight: 10
description: Point a repository's Git LFS at naraen and set up a developer's machine.
---

## Before you start

- The server is running and its operator has told you its host name, for example `lfs.example.com`, and the host key fingerprint.
- Your GitHub account is a member of the organisation the server syncs, and the SSH key you want to use is added to your GitHub account. The server only knows keys that GitHub lists for organisation members and repository deploy keys.

## Set the LFS address

In the repository, commit an `.lfsconfig`:

```sh
git config -f .lfsconfig lfs.url ssh://git@lfs.example.com/ORG/REPO
git config -f .lfsconfig lfs.locksverify false
git add .lfsconfig && git commit -m 'Use the naraen LFS server'
```

Use the repository's GitHub path, for `ORG/REPO`. The server also accepts the repository's previous paths after a rename. The `lfs.locksverify` setting stops Git LFS from calling the locks API, which naraen does not serve.

## Trust the host key

The first SSH connection asks you to trust the server's host key. Compare the fingerprint it shows with the one your operator published, then accept it. Never accept a fingerprint you have not checked.

## Make sure SSH offers the right key

Git LFS uses whatever key your SSH agent or default key file offers. If the key registered on GitHub is not your default, either load it into `ssh-agent` or add an entry to `~/.ssh/config`:

```
Host lfs.example.com
  IdentityFile ~/.ssh/id_ed25519_github
  IdentitiesOnly yes
```

The server accepts the first offered key it knows, so any key GitHub lists for you works.

## Check it works

```sh
git lfs push --all origin
```

If the server refuses you, [find out why]({{< relref "diagnose-a-refusal" >}}).

## Keep using HTTPS for code

Your code remote can stay on HTTPS. Only the LFS address uses SSH.
