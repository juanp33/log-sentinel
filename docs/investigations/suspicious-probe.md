# Investigation playbook: LS-002 suspicious probe

## Trigger

A request targets a sensitive path or a location commonly tested by opportunistic scanners, such as `/.env`, `/.git`, or `/wp-login.php`.

## Triage steps

1. Check that the response did not expose the requested file.
2. Review other requests from the same IP.
3. Confirm that backups, environment files, and VCS metadata are not public.
4. Check if the same paths appear in logs from other servers.
5. Record the finding and fix any confirmed exposure.

## Containment considerations

If a file was exposed, remove public access, rotate affected secrets, and review the server configuration.

## False-positive notes

Security researchers, internal scanners, and monitoring tools can generate similar requests.
