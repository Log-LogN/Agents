"""Draft Agent resolver — entity resolution and conflict handling."""

def resolve_contract_type(user_input: str) -> str:
    """Map fuzzy user input to a canonical contract type."""
    mapping = {
        "nda": "NDA", "non disclosure": "NDA", "confidentiality": "NDA",
        "msa": "MSA", "master services": "MSA", "master service": "MSA",
        "sow": "SOW", "statement of work": "SOW", "scope of work": "SOW",
        "vendor": "Vendor", "supplier": "Vendor", "procurement": "Vendor",
        "employment": "Employment", "employee": "Employment", "hiring": "Employment",
        "saas": "SaaS", "software": "SaaS", "license": "SaaS",
        "lease": "Lease", "rental": "Lease", "property": "Lease",
    }
    lower = user_input.lower()
    for key, val in mapping.items():
        if key in lower:
            return val
    return "Other"

def resolve_jurisdiction(user_input: str) -> str:
    """Normalize jurisdiction names."""
    mapping = {
        "ny": "New York", "new york": "New York",
        "ca": "California", "california": "California",
        "tx": "Texas", "texas": "Texas",
        "uk": "England & Wales", "england": "England & Wales",
        "eu": "European Union",
    }
    lower = user_input.lower()
    for key, val in mapping.items():
        if key in lower:
            return val
    return user_input.title()
