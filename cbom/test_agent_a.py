import unittest
import tempfile
import os
import json
import textwrap
from cbom.agent_a import generate_cbom

class TestAgentA(unittest.TestCase):
    def test_cbom_generation(self):
        with tempfile.TemporaryDirectory() as tempdir:
            # 1. Create a dummy Python file with hashlib and cryptography hashes and RSA key generation
            py_code = textwrap.dedent("""\
            import hashlib
            from hashlib import md5, new as hl_new
            from cryptography.hazmat.primitives.hashes import SHA512
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa
            from cryptography.hazmat.primitives.ciphers.algorithms import AES

            def dummy_func():
                # line 8: hashlib sha256
                h1 = hashlib.sha256()
                # line 10: hashlib md5 via import
                h2 = md5()
                # line 12: hashlib new sha1
                h3 = hl_new('sha1')
                # line 14: cryptography SHA512
                h4 = SHA512()
                # line 16: cryptography AES
                cipher = AES(b'somekey16bytes__')
                # line 18: RSA generate key size 2048
                priv_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                # line 20: DSA generate key size 1024
                priv_dsa = dsa.generate_private_key(key_size=1024)
            """)
            
            py_file_path = os.path.join(tempdir, "dummy_crypto.py")
            with open(py_file_path, "w", encoding="utf-8") as f:
                f.write(py_code)

            # 2. Create a dummy Go file with standard Go crypto calls
            go_code = textwrap.dedent("""\
            package main

            import (
                "crypto/aes"
                "crypto/md5"
                "crypto/rand"
                "crypto/rsa"
                "crypto/sha256"
            )

            func main() {
                // line 12: sha256.New
                h := sha256.New()
                // line 14: md5.Sum
                sum := md5.Sum([]byte("hello"))
                // line 16: aes.NewCipher
                block, _ := aes.NewCipher([]byte("1234567890123456"))
                // line 18: rsa.GenerateKey
                priv, _ := rsa.GenerateKey(rand.Reader, 4096)
            }
            """)
            
            go_file_path = os.path.join(tempdir, "dummy_crypto.go")
            with open(go_file_path, "w", encoding="utf-8") as f:
                f.write(go_code)

            # 3. Generate CBOM JSON
            cbom_json_path = os.path.join(tempdir, "cbom.json")
            bom = generate_cbom(tempdir, cbom_json_path)

            # Check if file was created
            self.assertTrue(os.path.exists(cbom_json_path))

            # 4. Load the generated JSON and perform assertions
            with open(cbom_json_path, "r", encoding="utf-8") as f:
                cbom_data = json.load(f)

            # Assert standard CycloneDX metadata
            self.assertIn("bomFormat", cbom_data)
            self.assertEqual(cbom_data["bomFormat"], "CycloneDX")
            self.assertEqual(cbom_data["specVersion"], "1.6")
            self.assertIn("components", cbom_data)

            components = cbom_data["components"]
            
            # Map of component name -> component details for assertions
            comp_map = {c["name"]: c for c in components}
            
            # Print components to verify
            print("Generated components names:", list(comp_map.keys()))

            # Verify component list contains expected algorithms
            expected_algos = ["SHA-256", "MD5", "SHA-1", "SHA-512", "AES", "RSA-2048", "DSA-1024", "RSA-4096"]
            for algo in expected_algos:
                self.assertIn(algo, comp_map, f"Missing expected algorithm {algo}")

            # Verify SHA-256 properties (from both Python and Go)
            sha256_comp = comp_map["SHA-256"]
            self.assertEqual(sha256_comp["type"], "cryptographic-asset")
            self.assertEqual(sha256_comp["cryptoProperties"]["assetType"], "algorithm")
            self.assertEqual(sha256_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "hash")
            
            # Verify occurrences for SHA-256 (sorted in test for determinism)
            sha256_occs = sorted(sha256_comp["evidence"]["occurrences"], key=lambda x: (x["location"], x["line"]))
            self.assertEqual(len(sha256_occs), 2)
            # Go SHA-256: dummy_crypto.go, line 13
            self.assertEqual(sha256_occs[0]["location"], "dummy_crypto.go")
            self.assertEqual(sha256_occs[0]["line"], 13)
            # Python SHA-256: dummy_crypto.py, line 9
            self.assertEqual(sha256_occs[1]["location"], "dummy_crypto.py")
            self.assertEqual(sha256_occs[1]["line"], 9)

            # Verify MD5 properties (from both Python and Go)
            md5_comp = comp_map["MD5"]
            self.assertEqual(md5_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "hash")
            md5_occs = sorted(md5_comp["evidence"]["occurrences"], key=lambda x: (x["location"], x["line"]))
            self.assertEqual(len(md5_occs), 2)
            # Go MD5: dummy_crypto.go, line 15
            self.assertEqual(md5_occs[0]["location"], "dummy_crypto.go")
            self.assertEqual(md5_occs[0]["line"], 15)
            # Python MD5: dummy_crypto.py, line 11
            self.assertEqual(md5_occs[1]["location"], "dummy_crypto.py")
            self.assertEqual(md5_occs[1]["line"], 11)

            # Verify AES properties
            aes_comp = comp_map["AES"]
            self.assertEqual(aes_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "block-cipher")
            aes_occs = sorted(aes_comp["evidence"]["occurrences"], key=lambda x: (x["location"], x["line"]))
            self.assertEqual(len(aes_occs), 2)
            # Go AES: dummy_crypto.go, line 17
            self.assertEqual(aes_occs[0]["location"], "dummy_crypto.go")
            self.assertEqual(aes_occs[0]["line"], 17)
            # Python AES: dummy_crypto.py, line 17
            self.assertEqual(aes_occs[1]["location"], "dummy_crypto.py")
            self.assertEqual(aes_occs[1]["line"], 17)

            # Verify RSA-2048 (Python)
            rsa2048_comp = comp_map["RSA-2048"]
            self.assertEqual(rsa2048_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "pke")
            self.assertEqual(rsa2048_comp["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"], "2048")
            rsa2048_occs = rsa2048_comp["evidence"]["occurrences"]
            self.assertEqual(len(rsa2048_occs), 1)
            self.assertEqual(list(rsa2048_occs)[0]["location"], "dummy_crypto.py")
            self.assertEqual(list(rsa2048_occs)[0]["line"], 19)

            # Verify RSA-4096 (Go)
            rsa4096_comp = comp_map["RSA-4096"]
            self.assertEqual(rsa4096_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "pke")
            self.assertEqual(rsa4096_comp["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"], "4096")
            rsa4096_occs = rsa4096_comp["evidence"]["occurrences"]
            self.assertEqual(len(rsa4096_occs), 1)
            self.assertEqual(list(rsa4096_occs)[0]["location"], "dummy_crypto.go")
            self.assertEqual(list(rsa4096_occs)[0]["line"], 19)

            # Verify DSA-1024
            dsa_comp = comp_map["DSA-1024"]
            self.assertEqual(dsa_comp["cryptoProperties"]["algorithmProperties"]["primitive"], "signature")
            self.assertEqual(dsa_comp["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"], "1024")
            dsa_occs = dsa_comp["evidence"]["occurrences"]
            self.assertEqual(len(dsa_occs), 1)
            self.assertEqual(list(dsa_occs)[0]["location"], "dummy_crypto.py")
            self.assertEqual(list(dsa_occs)[0]["line"], 21)

if __name__ == "__main__":
    unittest.main()
