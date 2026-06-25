Use a deployment-specific seccomp profile for production. The compose file already disables networking, drops capabilities, and uses no-new-privileges for the baseline.

