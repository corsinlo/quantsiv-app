"""CycloneDX 1.6 CBOM builder (A26) [tested in the audit: passes 1.6 strict validation].

Declared lifetimes are written as namespaced properties so they survive a round-trip (D6).
"""

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.output.json import JsonV1Dot6

LIFETIME_PROPERTY = "quantsiv:confidentiality-lifetime-years"
TRACK_PROPERTY = "quantsiv:track"

PRIMITIVE = {
    "signature": CryptoPrimitive.SIGNATURE,
    "key-agree": CryptoPrimitive.KEY_AGREE,
    "pke": CryptoPrimitive.PKE,
    "kem": CryptoPrimitive.KEM,
}
FUNCTIONS = {
    "signature": [CryptoFunction.SIGN, CryptoFunction.VERIFY],
    "key-agree": [CryptoFunction.KEYDERIVE],
    "pke": [CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT],
    "kem": [CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE],
}


def build_cbom(findings: list[dict], repo_full_name: str) -> str:
    """Findings carry `primitive` and, when scored, `track` and `lifetime_years`."""
    bom = Bom()  # valid urn:uuid serial number and tz-aware timestamp by default
    bom.metadata.component = Component(
        name=repo_full_name, type=ComponentType.APPLICATION, bom_ref="root"
    )
    for i, f in enumerate(findings):
        primitive = f.get("primitive") or "unknown"
        algo = AlgorithmProperties(
            primitive=PRIMITIVE.get(primitive, CryptoPrimitive.UNKNOWN),
            parameter_set_identifier=str(f["key_size"]) if f.get("key_size") else None,
            crypto_functions=FUNCTIONS.get(primitive, []),
            nist_quantum_security_level=0 if not f.get("quantum_safe") else None,
        )
        evidence = None
        if f.get("file_path"):
            evidence = ComponentEvidence(
                occurrences=[Occurrence(location=f["file_path"], line=f.get("line_number"))]
            )
        properties = []
        if f.get("track"):
            properties.append(Property(name=TRACK_PROPERTY, value=f["track"]))
        if f.get("track") == "HNDL" and f.get("lifetime_years") is not None:
            properties.append(Property(name=LIFETIME_PROPERTY, value=str(f["lifetime_years"])))
        bom.components.add(
            Component(
                bom_ref=f"crypto-{i}",
                name=f"{f['algorithm']}-{f['key_size']}" if f.get("key_size") else f["algorithm"],
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM, algorithm_properties=algo
                ),
                evidence=evidence,
                properties=properties,
            )
        )
    bom.register_dependency(bom.metadata.component, list(bom.components))
    return JsonV1Dot6(bom).output_as_string(indent=2)
