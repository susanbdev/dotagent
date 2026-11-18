---
name: polyglot-types-contract
description: Deterministic schema and TypeA<Origin> provenance contract rules for susanbdev/types without cross-repo bleed.
---

# Polyglot Types Provenance Contract

- **Provenance Typing (`TypeA<Untrusted>` vs `TypeA<Verified>`)**: Never coerce untrusted external/file strings into verified command or instruction types without deterministic parser validation.
- **Bounded Schemas**: Every string and collection field MUST declare explicit max byte/element bounds to eliminate token and memory exhaustion at the type boundary.
- **Repo Isolation**: Keep edits strictly inside the active repository; never traverse sibling repositories or generated dependency caches.
