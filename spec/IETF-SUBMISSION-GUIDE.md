# IETF Internet-Draft Submission Guide

## For: draft-grotowski-aps-01

**Agent Passport Standard (APS) v1.1**
**Author:** Cezary Grotowski <c.grotowski@gmail.com>

---

## 1. Create an IETF Datatracker Account

1. Go to https://datatracker.ietf.org/accounts/create/
2. Register with your email (c.grotowski@gmail.com)
3. Confirm your email address
4. Complete your profile with full name and affiliation

## 2. Convert to xml2rfc Format

The IETF requires submissions in xml2rfc (RFC XML v3) format. Two recommended approaches:

### Option A: kramdown-rfc (Markdown → XML)

```bash
# Install kramdown-rfc
gem install kramdown-rfc

# Convert the draft
kramdown-rfc2629 draft-grotowski-aps-01.md > draft-grotowski-aps-01.xml

# Validate and render
xml2rfc draft-grotowski-aps-01.xml --text
xml2rfc draft-grotowski-aps-01.xml --html
```

**Note:** kramdown-rfc expects a YAML front matter block (already present in the v1 draft). You may need to adapt the v1.1 draft to include the YAML metadata header from `draft-grotowski-aps-v1.md`.

### Option B: Manual XML authoring

Use the RFC XML v3 vocabulary (RFC 7991):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rfc xmlns:xi="http://www.w3.org/2001/XInclude"
     docName="draft-grotowski-aps-01"
     category="std"
     ipr="trust200902"
     submissionType="IETF">
  <front>
    <title>Agent Passport Standard (APS) v1.1</title>
    <author fullname="Cezary Grotowski"
            initials="C."
            surname="Grotowski">
      <organization>ClawBotDen</organization>
      <address>
        <email>c.grotowski@gmail.com</email>
      </address>
    </author>
    <date year="2026" month="February" day="16"/>
    <abstract>
      <t>This document defines the Agent Passport Standard...</t>
    </abstract>
  </front>
  <middle>
    <!-- sections here -->
  </middle>
  <back>
    <references>
      <!-- references here -->
    </references>
  </back>
</rfc>
```

### Option C: Use the online tool

- https://author-tools.ietf.org/ — upload markdown or XML, get rendered output
- Validates format compliance automatically

### Install xml2rfc locally

```bash
pip install xml2rfc
xml2rfc --version  # should be 3.x+
```

## 3. Submit via Datatracker

1. Go to https://datatracker.ietf.org/submit/
2. Log in with your account
3. Upload the XML file (or txt if generated)
4. The system will:
   - Validate the format (idnits checks)
   - Extract metadata
   - Generate text and HTML renderings
   - Assign a submission ID
5. Confirm the submission
6. You'll receive an email confirmation with a link to your draft

### Pre-submission checklist

- [ ] Document name follows convention: `draft-grotowski-aps-01`
- [ ] Abstract is present and concise
- [ ] All RFC 2119 keywords used correctly
- [ ] References are complete (normative and informative)
- [ ] Authors' addresses section is present
- [ ] No lines exceed 72 characters (for text rendering)
- [ ] Run `idnits` tool for compliance check:
  ```bash
  pip install idnits
  idnits draft-grotowski-aps-01.txt
  ```

## 4. Target Working Group

### Primary: RATS (Remote ATtestation procedureS)

- **Charter:** https://datatracker.ietf.org/wg/rats/about/
- **Relevance:** RATS focuses on attestation evidence for computing environments. APS Execution Attestation (§20) and trust level verification directly align.
- **Chairs:** Contact rats-chairs@ietf.org
- **Mailing list:** rats@ietf.org (subscribe first)
- **Action:** Email the chairs with a brief introduction of APS and request agenda time at the next IETF meeting.

### Alternative: New Birds-of-a-Feather (BoF)

If RATS scope is too narrow for the full APS specification:

1. **Propose a BoF** at an upcoming IETF meeting
2. **Suggested name:** AITS (AI Trust and Security) or AGID (Agent Identity)
3. **Requirements for BoF:**
   - A clear problem statement
   - Evidence of community interest (implementations, supporters)
   - A draft charter for a potential working group
   - At least one Internet-Draft (this document)
4. **Process:**
   - Contact the relevant Area Director (Security Area for this topic)
   - Submit a BoF request via https://datatracker.ietf.org/meeting/requests
   - Deadline is typically 8 weeks before the IETF meeting

### Other relevant groups

- **OAUTH** — if focusing on the delegation/authorization aspects
- **SCITT** (Supply Chain Integrity, Transparency and Trust) — for provenance aspects
- **JOSE** (JSON Object Signing and Encryption) — for cryptographic format alignment

## 5. Timeline Expectations

| Milestone | Estimated Time |
|-----------|---------------|
| First submission (individual draft) | Immediate |
| Presentation at IETF meeting | Next IETF meeting (3-6 months) |
| Adoption as WG document | 6-12 months after first presentation |
| WG Last Call | 12-24 months after adoption |
| IESG Review | 2-6 months after WG Last Call |
| RFC publication | 3-6 months after IESG approval |
| **Total: Individual draft → RFC** | **2-4 years** |

### Accelerating the process

1. **Get co-authors** — especially from established IETF participants
2. **Build implementations** — multiple independent implementations strengthen the case
3. **Engage the community** — present at side meetings, hackathons
4. **Iterate quickly** — submit updated drafts (-02, -03, etc.) every 2-3 months
5. **Address feedback** — respond to every review comment on the mailing list

## 6. IETF Meeting Schedule

IETF meets three times per year. Check https://www.ietf.org/meeting/ for upcoming meetings. Deadlines for draft submission before a meeting are typically 2 weeks prior.

## 7. Resources

- **IETF Newcomers Guide:** https://www.ietf.org/about/participate/get-started/
- **RFC Style Guide:** https://www.rfc-editor.org/rfc/rfc7322
- **xml2rfc Documentation:** https://xml2rfc.tools.ietf.org/
- **kramdown-rfc:** https://github.com/cabo/kramdown-rfc
- **Author Tools:** https://author-tools.ietf.org/
- **ID Checklist:** https://www.ietf.org/id-info/checklist.html
- **Datatracker:** https://datatracker.ietf.org/
