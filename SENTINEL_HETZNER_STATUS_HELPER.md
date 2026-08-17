# Sentinel Hetzner Read-only Status Helper

## Purpose

`sentinel_hetzner_status_helper.py` provides narrow, read-only summaries for Hetzner local status checks that often require elevated read access.

It is intended for the Hetzner server agent only:

```text
sentinel_hetzner_local_agent.py -> sentinel_hetzner_status_helper.py -> local status commands
```

## Allowed Commands

The helper exposes only these subcommands:

- `ufw-status`: runs `ufw status verbose` and reports only active/inactive summary state.
- `fail2ban-status`: runs `fail2ban-client status` and reports aggregate jail names.
- `fail2ban-sshd`: runs `fail2ban-client status sshd` and reports aggregate counters only.
- `sentinel-timers`: runs `systemctl is-active` for the allowlisted Sentinel timer units.

## Forbidden Behavior

The helper must not:

- change UFW rules
- ban or unban fail2ban entries
- start, stop, restart, reload, or enable services
- read `/etc/sentinel-defense.env`
- read SSH key contents
- print raw logs, IP lists, credentials, or secrets
- contact external hosts

## Manual Sudoers Pattern

No sudoers change is applied by this repository. If elevated read access is desired, review and install a narrow local sudoers entry manually.

Example pattern, adjusted to the exact reviewed path:

```text
deploy ALL=(root) NOPASSWD: /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py ufw-status, /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py fail2ban-status, /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py fail2ban-sshd, /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py sentinel-timers
```

Use `sudo -n` only. If a password is required, the agent must not automate password entry; it should fall back to non-secret local evidence such as systemd active state and report the limitation.

## Local Checks

Run without elevation first:

```bash
cd /srv/sentinel-defense
python3 sentinel_hetzner_status_helper.py ufw-status --pretty
python3 sentinel_hetzner_status_helper.py fail2ban-status --pretty
python3 sentinel_hetzner_status_helper.py fail2ban-sshd --pretty
python3 sentinel_hetzner_status_helper.py sentinel-timers --pretty
```

If manually reviewed sudoers exists:

```bash
sudo -n /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py ufw-status --pretty
sudo -n /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py fail2ban-status --pretty
sudo -n /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py fail2ban-sshd --pretty
sudo -n /usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_status_helper.py sentinel-timers --pretty
```

## Reporting Semantics

If UFW or fail2ban is confirmed active, unreadable direct command output is not by itself a `WARNING`.

If exact helper output is unavailable, the Hetzner agent may classify active `systemctl` evidence as informational and continue to report the missing helper detail separately.

`/etc/sentinel-defense.env` mode `0640 root:deploy` is acceptable when the deploy-run daily mailer must read it. World-readable remains `CRITICAL`, and group/world-writable remains `CRITICAL`.

Missing `/home/deploy/.ssh/authorized_keys` is informational when deploy-user key login is intentionally disabled or managed elsewhere. The agent must not create keys and must not read key contents.
