# Policy Language

Policies are YAML files under `config/policies`. Rules are sorted by descending `priority` and then by `id`, making resolution deterministic.

Supported condition fields in this milestone:

- `category`
- `type`
- `state`
- `state_in`
- `reason_code`
- `severity_in`
- `greater_than_or_equal`

If no rule matches, the default action is `ALLOW_RECONSTRUCTED_ONLY`. The original upload remains quarantined.

