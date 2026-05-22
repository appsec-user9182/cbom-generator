import os
import json
import shutil
import zipfile
import unittest
from trailmark.query.api import QueryEngine
from cbom.agent_c import analyze_cbom, find_node_by_location

class TestDeterministicJunctionEngine(unittest.TestCase):
    def setUp(self):
        # Create a mock target directory for testing
        self.mock_dir = "test_mock_target"
        os.makedirs(self.mock_dir, exist_ok=True)
        
        # 1. entrypoint.py: Has the public API entrypoint
        with open(os.path.join(self.mock_dir, "entrypoint.py"), "w", encoding="utf-8") as f:
            f.write("from .core import process_request\n\ndef handle_api_call():\n    process_request()\n")
            
        # 2. core.py: Internal execution chain
        with open(os.path.join(self.mock_dir, "core.py"), "w", encoding="utf-8") as f:
            f.write("from .crypto import encrypt_data\n\ndef process_request():\n    encrypt_data()\n")
            
        # 3. crypto.py: Contains the cryptographic flaw node
        with open(os.path.join(self.mock_dir, "crypto.py"), "w", encoding="utf-8") as f:
            f.write("def encrypt_data():\n    # Flaw location line 2\n    pass\n")
            
        # Initialize QueryEngine from the mock directory
        self.engine = QueryEngine.from_directory(self.mock_dir, language="auto")
        
        # Manually define entrypoints in the graph
        self.engine._store._graph.entrypoints["entrypoint:handle_api_call"] = True
        
        # Create a dummy cbom.json file
        self.cbom_path = "test_cbom.json"
        cbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "name": "SHA-1",
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto/algorithm/sha-1",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "name": "SHA-1"
                        }
                    },
                    "properties": [
                        {"name": "file", "value": "test_mock_target/crypto.py"},
                        {"name": "line", "value": "2"}
                    ]
                },
                {
                    "name": "MD5",
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto/algorithm/md5",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "name": "MD5"
                        }
                    },
                    "properties": [
                        {"name": "file", "value": "test_mock_target/legacy.py"},
                        {"name": "line", "value": "12"}
                    ]
                }
            ]
        }
        with open(self.cbom_path, "w", encoding="utf-8") as f:
            json.dump(cbom_data, f, indent=2)
            
        # Output directory for test results
        self.output_dir = "test_output"
        os.makedirs(self.output_dir, exist_ok=True)

    def tearDown(self):
        # Clean up temporary test files and directories
        for path in [self.mock_dir, self.cbom_path, self.output_dir]:
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)

    def test_find_node_by_location(self):
        # Test finding the target function node by exact location coordinate
        nodes = find_node_by_location(self.engine, "test_mock_target/crypto.py", 2)
        self.assertTrue(len(nodes) >= 1)
        node_ids = [n.id for n in nodes]
        self.assertIn("crypto:encrypt_data", node_ids)

    def test_junction_engine_analysis(self):
        # Run the full path junction analysis
        results = analyze_cbom(
            cbom_path=self.cbom_path,
            engine=self.engine,
            output_dir=self.output_dir
        )
        
        # Verify reachability of SHA-1 flaw
        self.assertIn("crypto:encrypt_data", results)
        flaw_info = results["crypto:encrypt_data"]
        self.assertEqual(flaw_info["crypto_primitive"], "SHA-1")
        self.assertEqual(flaw_info["exact_location"], "test_mock_target/crypto.py:2")
        
        # Check that the call path is discovered and mapped
        expected_path = ["entrypoint:handle_api_call", "core:process_request", "crypto:encrypt_data"]
        self.assertIn(expected_path, flaw_info["exposed_entrypoints"])
        
        # Verify that MD5 is correctly classified as unreachable/static library import
        self.assertIn("Unreachable/Static Library Import", results)
        unreachable_list = results["Unreachable/Static Library Import"]
        self.assertEqual(len(unreachable_list), 1)
        self.assertEqual(unreachable_list[0]["crypto_primitive"], "MD5")
        self.assertEqual(unreachable_list[0]["exact_location"], "test_mock_target/legacy.py:12")
        
        # Verify generated output files
        blast_json_path = os.path.join(self.output_dir, "blast_radius.json")
        visual_html_path = os.path.join(self.output_dir, "visual_map.html")
        zip_path = os.path.join(self.output_dir, "blast_radius.zip")
        
        self.assertTrue(os.path.exists(blast_json_path))
        self.assertTrue(os.path.exists(visual_html_path))
        self.assertTrue(os.path.exists(zip_path))
        
        # Check that visual_map.html has SVG content
        with open(visual_html_path, "r", encoding="utf-8") as f:
            html = f.read()
            self.assertIn("<svg", html)
            self.assertIn("class=\"legend\"", html)
            # Ensure the styling rules are embedded in the visual map
            self.assertIn("Public Entry Point", html)
            self.assertIn("Internal Execution Chain", html)
            self.assertIn("Cryptographic Flaw Node (Dark Charcoal)", html)
            
        # Verify ZIP archive contents
        with zipfile.ZipFile(zip_path, 'r') as zf:
            namelist = zf.namelist()
            self.assertIn("blast_radius.json", namelist)
            self.assertIn("visual_map.html", namelist)

if __name__ == "__main__":
    unittest.main()
