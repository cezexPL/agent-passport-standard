# APS Python SDK

Python SDK for the **Agent Passport Standard** v0.1.

## Install

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from aps import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage, generate_key_pair

pub, priv = generate_key_pair()
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

passport = AgentPassport.new(PassportConfig(
    id="did:key:z6MkExample",
    public_key=pub_hex,
    owner_did="did:key:z6MkOwner",
    skills=[Skill("python", "1.0.0", "Python dev", ["code_write"], "0x" + "ab" * 32)],
    soul=Soul("focused", "tdd", [], "0x" + "cd" * 32),
    policies=Policies("0x" + "ef" * 32, ["can_bid"]),
    lineage=Lineage("original", [], 0),
))

passport.sign(priv)
assert passport.verify(pub)
```

## Tests

```bash
python -m pytest tests/ -v
```
