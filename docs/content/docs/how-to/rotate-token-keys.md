---
title: Rotate the token keys
weight: 70
description: Replace the key that signs LFS tokens without refusing anyone.
---

Tokens are signed with the first key in the token keys file. Later keys only verify, so you can add a new key without invalidating tokens that are already out.

1. Add a new line at the **top** of the file:

   ```
   k2 <new secret, 64 hex digits>
   k1 <old secret>
   ```

2. Restart the server. New tokens are signed with `k2`, and tokens signed with `k1` still verify.
3. After 15 minutes, which is the token lifetime, remove the `k1` line and restart again.

The saved copy of the permissions snapshot is signed with the token keys too, and a restarting server verifies it against any listed key. If you want a replacement server to restore a copy written before the rotation, leave the old key listed until the next change has been saved under the new one.
