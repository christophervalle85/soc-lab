# Lab Safety Boundaries

## Authorized Systems Only

- All simulations must run only on systems owned and controlled by the project
  owner.
- No public, third-party, workplace, school, or production systems may be
  scanned, tested, or targeted.
- Attack simulations must remain inside the isolated laboratory.

## Virtual-Machine Safety

- Create a virtual-machine snapshot before higher-risk simulations.
- Review every test command before execution.
- Every simulation must include cleanup instructions.
- Stop a test if it behaves differently from its documented purpose.

## Network Safety

- Intentionally vulnerable services must not be exposed directly to the public
  internet.
- Bridged networking will not be used unless there is a documented reason.
- The laboratory should use NAT, host-only, or an isolated internal network as
  appropriate.

## Credential and Data Safety

- Credentials, API keys, tokens, and private information must never be
  committed to Git.
- Use only synthetic data and dedicated laboratory accounts.
- Sanitize logs before publishing them.
- Do not reuse personal passwords inside the laboratory.

## Documentation

For every simulation, document:

- Purpose
- Target system
- MITRE ATT&CK mapping
- Commands executed
- Expected telemetry
- Cleanup procedure
- Validation result
