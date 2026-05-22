import os
import ast
import re
from typing import List, Dict, Tuple, Any, Optional

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType, CryptoProperties
from cyclonedx.model.crypto import CryptoAssetType, CryptoPrimitive, AlgorithmProperties
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion

# Normalization mapping for various algorithm representation names
NORMALIZE_ALGO = {
    "sha1": "SHA-1",
    "md5": "MD5",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "aes": "AES",
    "tripledes": "3DES",
    "des": "DES",
    "rsa": "RSA",
    "dsa": "DSA",
    "ecdsa": "ECDSA",
}

def normalize_algorithm(name: str) -> str:
    name_clean = name.strip()
    name_lower = name_clean.lower().replace("-", "").replace("_", "")
    if name_lower in NORMALIZE_ALGO:
        return NORMALIZE_ALGO[name_lower]
    
    # Check for rsaXXXX or dsaXXXX patterns
    m = re.match(r'^(rsa|dsa)(\d+)$', name_lower)
    if m:
        algo_type = m.group(1).upper()
        bits = m.group(2)
        return f"{algo_type}-{bits}"
    return name_clean

class PythonCryptoVisitor(ast.NodeVisitor):
    """
    AST Visitor to scan Python source code for cryptographic algorithm imports and invocations.
    """
    def __init__(self, file_path: str, target_dir: str):
        self.file_path = file_path
        self.target_dir = target_dir
        self.rel_path = os.path.relpath(file_path, target_dir)
        self.imports: Dict[str, str] = {}
        self.found_assets: List[Dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports[local_name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def resolve_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            prefix = self.resolve_name(node.value)
            if prefix:
                return f"{prefix}.{node.attr}"
        return None

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self.resolve_name(node.func)
        if resolved:
            self.check_call(resolved, node)
        self.generic_visit(node)

    def add_asset(self, algorithm: str, primitive: CryptoPrimitive, lineno: int, key_size: Optional[int] = None) -> None:
        self.found_assets.append({
            "algorithm": algorithm,
            "primitive": primitive,
            "asset_type": CryptoAssetType.ALGORITHM,
            "location": self.rel_path,
            "line": lineno,
            "key_size": key_size
        })

    def check_call(self, resolved: str, node: ast.Call) -> None:
        # 1. hashlib hash functions
        hashlib_hash_funcs = {
            "hashlib.md5": ("MD5", CryptoPrimitive.HASH),
            "hashlib.sha1": ("SHA-1", CryptoPrimitive.HASH),
            "hashlib.sha224": ("SHA-224", CryptoPrimitive.HASH),
            "hashlib.sha256": ("SHA-256", CryptoPrimitive.HASH),
            "hashlib.sha384": ("SHA-384", CryptoPrimitive.HASH),
            "hashlib.sha512": ("SHA-512", CryptoPrimitive.HASH),
            "hashlib.sha3_224": ("SHA3-224", CryptoPrimitive.HASH),
            "hashlib.sha3_256": ("SHA3-256", CryptoPrimitive.HASH),
            "hashlib.sha3_384": ("SHA3-384", CryptoPrimitive.HASH),
            "hashlib.sha3_512": ("SHA3-512", CryptoPrimitive.HASH),
            "hashlib.blake2b": ("BLAKE2b", CryptoPrimitive.HASH),
            "hashlib.blake2s": ("BLAKE2s", CryptoPrimitive.HASH),
        }

        if resolved in hashlib_hash_funcs:
            algo, prim = hashlib_hash_funcs[resolved]
            self.add_asset(algo, prim, node.lineno)
            return

        # hashlib.new(name, ...)
        if resolved == "hashlib.new":
            algo_name = None
            if len(node.args) > 0:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    algo_name = arg0.value
            if not algo_name:
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        algo_name = kw.value.value
                        break
            if algo_name:
                algo = normalize_algorithm(algo_name)
                self.add_asset(algo, CryptoPrimitive.HASH, node.lineno)
            return

        # 2. cryptography hazmat hashes
        cryptography_hashes = {
            "cryptography.hazmat.primitives.hashes.MD5": ("MD5", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA1": ("SHA-1", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA224": ("SHA-224", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA256": ("SHA-256", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA384": ("SHA-384", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA512": ("SHA-512", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA3_224": ("SHA3-224", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA3_256": ("SHA3-256", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA3_384": ("SHA3-384", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.SHA3_512": ("SHA3-512", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.BLAKE2b": ("BLAKE2b", CryptoPrimitive.HASH),
            "cryptography.hazmat.primitives.hashes.BLAKE2s": ("BLAKE2s", CryptoPrimitive.HASH),
        }

        if resolved in cryptography_hashes:
            algo, prim = cryptography_hashes[resolved]
            self.add_asset(algo, prim, node.lineno)
            return

        # 3. cryptography symmetric ciphers (algorithms)
        cryptography_ciphers = {
            "cryptography.hazmat.primitives.ciphers.algorithms.AES": ("AES", CryptoPrimitive.BLOCK_CIPHER),
            "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": ("3DES", CryptoPrimitive.BLOCK_CIPHER),
            "cryptography.hazmat.primitives.ciphers.algorithms.Camellia": ("Camellia", CryptoPrimitive.BLOCK_CIPHER),
            "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20": ("ChaCha20", CryptoPrimitive.STREAM_CIPHER),
        }

        if resolved in cryptography_ciphers:
            algo, prim = cryptography_ciphers[resolved]
            self.add_asset(algo, prim, node.lineno)
            return

        # 4. cryptography asymmetric (RSA, DSA, EC)
        if resolved == "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key":
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                    key_size = kw.value.value
                    break
            if key_size is None and len(node.args) > 1:
                arg1 = node.args[1]
                if isinstance(arg1, ast.Constant) and isinstance(arg1.value, int):
                    key_size = arg1.value
            algo = f"RSA-{key_size}" if key_size else "RSA"
            self.add_asset(algo, CryptoPrimitive.PKE, node.lineno, key_size=key_size)
            return

        if resolved == "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key":
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                    key_size = kw.value.value
                    break
            if key_size is None and len(node.args) > 0:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, int):
                    key_size = arg0.value
            algo = f"DSA-{key_size}" if key_size else "DSA"
            self.add_asset(algo, CryptoPrimitive.SIGNATURE, node.lineno, key_size=key_size)
            return

        if resolved == "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key":
            self.add_asset("ECDSA", CryptoPrimitive.SIGNATURE, node.lineno)
            return

        # 5. pycryptodome mappings
        pycryptodome_mappings = {
            "Crypto.Cipher.AES.new": ("AES", CryptoPrimitive.BLOCK_CIPHER),
            "Crypto.Cipher.DES.new": ("DES", CryptoPrimitive.BLOCK_CIPHER),
            "Crypto.Cipher.DES3.new": ("3DES", CryptoPrimitive.BLOCK_CIPHER),
            "Crypto.Hash.MD5.new": ("MD5", CryptoPrimitive.HASH),
            "Crypto.Hash.SHA1.new": ("SHA-1", CryptoPrimitive.HASH),
            "Crypto.Hash.SHA256.new": ("SHA-256", CryptoPrimitive.HASH),
            "Crypto.Hash.SHA512.new": ("SHA-512", CryptoPrimitive.HASH),
            "Crypto.PublicKey.RSA.generate": ("RSA", CryptoPrimitive.PKE),
        }
        if resolved in pycryptodome_mappings:
            algo, prim = pycryptodome_mappings[resolved]
            key_size = None
            if resolved == "Crypto.PublicKey.RSA.generate":
                for kw in node.keywords:
                    if kw.arg == "bits" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        key_size = kw.value.value
                        break
                if key_size is None and len(node.args) > 0:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, int):
                        key_size = arg0.value
                algo = f"RSA-{key_size}" if key_size else "RSA"
                self.add_asset(algo, prim, node.lineno, key_size=key_size)
            else:
                self.add_asset(algo, prim, node.lineno)
            return

def scan_python_file(file_path: str, target_dir: str) -> List[Dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return []
    
    visitor = PythonCryptoVisitor(file_path, target_dir)
    visitor.visit(tree)
    return visitor.found_assets

# Go package scan regex pattern mappings
GO_PATTERNS = [
    (r'\bsha256\.New\b|\bsha256\.Sum256\b', "SHA-256", CryptoPrimitive.HASH),
    (r'\bmd5\.New\b|\bmd5\.Sum\b', "MD5", CryptoPrimitive.HASH),
    (r'\bsha1\.New\b|\bsha1\.Sum\b', "SHA-1", CryptoPrimitive.HASH),
    (r'\bsha512\.New384\b|\bsha512\.Sum384\b', "SHA-384", CryptoPrimitive.HASH),
    (r'\bsha512\.New\b|\bsha512\.Sum512\b', "SHA-512", CryptoPrimitive.HASH),
    (r'\baes\.NewCipher\b', "AES", CryptoPrimitive.BLOCK_CIPHER),
    (r'\bdes\.NewTripleDESCipher\b', "3DES", CryptoPrimitive.BLOCK_CIPHER),
    (r'\bdes\.NewCipher\b', "DES", CryptoPrimitive.BLOCK_CIPHER),
    (r'\bdsa\.GenerateKey\b|\bdsa\.GenerateParameters\b', "DSA", CryptoPrimitive.SIGNATURE),
    (r'\becdsa\.GenerateKey\b', "ECDSA", CryptoPrimitive.SIGNATURE),
]

def scan_go_file(file_path: str, target_dir: str) -> List[Dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    rel_path = os.path.relpath(file_path, target_dir)
    found_assets = []
    
    for idx, line in enumerate(lines):
        line_num = idx + 1
        # Strip single-line comments
        line_code = line.split("//")[0]
        
        # Check RSA first
        if "rsa.GenerateKey" in line_code:
            match = re.search(r'\brsa\.GenerateKey\s*\(\s*[^,]+,\s*(\d+)\)', line_code)
            if match:
                bits = int(match.group(1))
                found_assets.append({
                    "algorithm": f"RSA-{bits}",
                    "primitive": CryptoPrimitive.PKE,
                    "asset_type": CryptoAssetType.ALGORITHM,
                    "location": rel_path,
                    "line": line_num,
                    "key_size": bits
                })
            else:
                found_assets.append({
                    "algorithm": "RSA",
                    "primitive": CryptoPrimitive.PKE,
                    "asset_type": CryptoAssetType.ALGORITHM,
                    "location": rel_path,
                    "line": line_num,
                    "key_size": None
                })
            continue

        # Check other patterns
        for pattern, algo, prim in GO_PATTERNS:
            if re.search(pattern, line_code):
                found_assets.append({
                    "algorithm": algo,
                    "primitive": prim,
                    "asset_type": CryptoAssetType.ALGORITHM,
                    "location": rel_path,
                    "line": line_num,
                    "key_size": None
                })
                
    return found_assets

def scan_directory(target_dir: str) -> List[Dict[str, Any]]:
    assets = []
    for root, dirs, files in os.walk(target_dir):
        # Skip dot directories to avoid noise
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".py"):
                assets.extend(scan_python_file(file_path, target_dir))
            elif file.endswith(".go"):
                assets.extend(scan_go_file(file_path, target_dir))
    return assets

def scan_target(target_path: str) -> List[Dict[str, Any]]:
    if os.path.isfile(target_path):
        target_dir = os.path.dirname(target_path) or "."
        if target_path.endswith(".py"):
            return scan_python_file(target_path, target_dir)
        elif target_path.endswith(".go"):
            return scan_go_file(target_path, target_dir)
        return []
    else:
        return scan_directory(target_path)

def generate_cbom(target_dir: str, output_path: str = "cbom.json") -> Bom:
    """
    Statically scans target_dir for cryptographic assets and serializes a CycloneDX Bom
    to output_path.
    """
    if not os.path.exists(target_dir):
        raise ValueError(f"Target path '{target_dir}' does not exist.")

    assets = scan_target(target_dir)

    # Group occurrences by (algorithm, primitive, asset_type, key_size)
    grouped_assets: Dict[Tuple[str, CryptoPrimitive, CryptoAssetType, Optional[int]], List[Dict[str, Any]]] = {}
    for asset in assets:
        key = (asset["algorithm"], asset["primitive"], asset["asset_type"], asset["key_size"])
        if key not in grouped_assets:
            grouped_assets[key] = []
        grouped_assets[key].append(asset)

    bom = Bom()

    for key, occurrences in grouped_assets.items():
        algorithm, primitive, asset_type, key_size = key
        
        algo_props = AlgorithmProperties(primitive=primitive)
        if key_size is not None:
            algo_props.parameter_set_identifier = str(key_size)
            
        crypto_props = CryptoProperties(
            asset_type=asset_type,
            algorithm_properties=algo_props
        )
        
        # Sort occurrences to be deterministic
        sorted_occurrences = sorted(occurrences, key=lambda x: (x["location"], x["line"]))
        
        occurrences_list = []
        for occ in sorted_occurrences:
            occurrences_list.append(
                Occurrence(
                    location=occ["location"],
                    line=occ["line"]
                )
            )
            
        evidence = ComponentEvidence(occurrences=occurrences_list)
        
        comp = Component(
            name=algorithm,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            crypto_properties=crypto_props,
            evidence=evidence,
            bom_ref=f"crypto-asset-{algorithm.lower().replace(' ', '-')}"
        )
        bom.components.add(comp)

    # Output Bom to JSON using OutputFormat.JSON and SchemaVersion.V1_6
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    outputter.output_to_file(output_path, allow_overwrite=True)
    print(f"Successfully generated CBOM at '{output_path}'")
    
    return bom

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    output = sys.argv[2] if len(sys.argv) > 2 else "cbom.json"
    generate_cbom(target, output)
