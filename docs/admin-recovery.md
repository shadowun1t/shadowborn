# Administration and recovery

## Managed gateways

`deployment status` reads the current transaction. A pending apply arms a
120-second systemd timer. Reboot recovery runs before reconciliation. Lost SSH
or an expired trial can be diagnosed from the previously verified console.

```bash
sudo shadowborn status
sudo shadowborn deployment status
sudo shadowborn deployment recover
```

An explicit recovery reverts a pending deployment. On a committed gateway use
`deployment reconcile` after a partial peer change. The protected canonical
authorization file drives the WG config, running peer set and nft address set.
A changed owned file or live firewall stops the operation for console review.
On a compromised device, revoke its identity and enroll fresh keys. Old bundles
and decrypted profile copies remain under the operator's custody.

For an on-demand diagnosis, the local root console can inspect current kernel
fields with `wg show wg-shadowborn latest-handshakes` and
`wg show wg-shadowborn transfer`. They display peer public keys alongside
current handshake times or byte totals. Keep the output on that console.
The gateway takes no samples, schedules no collection and writes no history.
Use a real enrolled client and an owned HTTPS origin to check DNS and the exit
address independently.

To remove a managed deployment, verify the console and run:

```bash
sudo shadowborn uninstall --plan
sudo shadowborn deployment remove --console-verified --confirm
sudo ./scripts/uninstall-server.sh
```

Removal checks file/table ownership, stops and disables the managed services,
and restores the recorded forwarding baseline. Canonical secrets, configuration
and revocations stay in place. To update the file-only package, use the same
teardown followed by `update-server.sh`, review the new plan and activate again.

## Offline restore and encrypted backups

Backups contain necessary configuration and credentials. A disabled/revoked
identity stays restricted when restoring an older backup to the same gateway.

```bash
sudo shadowborn backup --recipient AGE_RECIPIENT --output /root/gateway.age
sudo shadowborn restore --input /root/gateway.age --identity /root/operator.agekey --dry-run
sudo shadowborn restore --input /root/gateway.age --identity /root/operator.agekey --confirm
```

Native age identities and encrypted inputs must be private 0600 files under
private 0700 directories. Restore requires the existing same gateway key/config
and unions current disabled/revoked restrictions into the backup; conflicts abort.
It cannot restore an empty new server because there is no local revocation ledger
to compare. Full disaster-rebuild reconciliation is a release gate, not an
implicit permission to reauthorize credentials from an old backup.

Keep encrypted off-host backups with explicit retention. Package update snapshots
contain program/docs only, no peer activity. If packaging leaves `pending/`,
inspect before.json and numbered copies, compare current files, and manually
restore only unchanged owned paths. The installer refuses a new operation until
that interruption is resolved; it does not force over an administrator's edits.

## Manual VM emergency actions

From the verified console, stop `wg-quick@wg-shadowborn` to prevent all peer egress
while fixing a compromised/revoked credential. Stop its DNS unit too. Remove the
peer from the persisted WG file and its address from the firewall peers set;
regenerate the offline state/bundle only after detaching the manual deployment.
A live `wg set INTERFACE peer PUBLIC_KEY remove` alone is insufficient: restart
would reauthorize the old config. Do not restore a snapshot containing an old
peer inventory without reconciling every revocation.

For manual uninstall: stop/disable the three dedicated units, remove only the
exact generated WG config, WG per-instance drop-in, owned DNS/firewall units and
owned sysctl drop-in. Restore the original forwarding value only after comparing
it with the value this deployment set and considering other forwarding users.
Remove only `inet shadowborn` and `ip shadowborn_nat` after checking ownership.
Do not flush rulesets, uninstall shared dependencies or delete system logs. Use
the VM snapshot/console when ownership is ambiguous. After detaching the manual
network deployment, file-only `scripts/uninstall-server.sh` removes the package.
Configuration, encrypted backups and revocation state are deliberately retained.
