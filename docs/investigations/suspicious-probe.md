# Investigation playbook: LS-002 suspicious probe

## Trigger

A request targets a sensitive path or a location commonly tested by opportunistic scanners, such as `/.env`, `/.git`, or `/wp-login.php`.

## Triage steps

1. Confirm that the response status did not expose the requested resource.
2. Review adjacent requests from the source IP for enumeration or exploitation attempts.
3. Verify that the application and web server do not publish backups, environment files, or VCS metadata.
4. Check whether the same paths appear in other assets' logs.
5. Record the finding and remediate confirmed exposure through the normal change process.

## Containment considerations

If exposure is confirmed, remove public access, rotate any disclosed secrets, invalidate affected credentials, and review server configuration.

## False-positive notes

Security researchers, internal vulnerability scanners, and monitoring tools can legitimately generate probe-like requests.
