import os
import sys
import json
import shutil
import tempfile
import unittest

# Ensure the project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cbom.agent_b import generate_codegraph

class TestAgentB(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the target repository
        self.test_dir = tempfile.mkdtemp()
        
        # Create a simple module structure
        self.utils_content = """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""
        
        self.main_content = """
from utils import add

def compute():
    x = add(2, 3)
    return x

def run():
    res = compute()
    print(res)
"""
        
        with open(os.path.join(self.test_dir, "utils.py"), "w") as f:
            f.write(self.utils_content)
            
        with open(os.path.join(self.test_dir, "main.py"), "w") as f:
            f.write(self.main_content)
            
        # Output JSON path
        self.output_json = os.path.join(self.test_dir, "codegraph.json")

    def tearDown(self):
        # Clean up temporary directory
        shutil.rmtree(self.test_dir)

    def test_generate_codegraph(self):
        # Generate the codegraph using our agent_b function
        engine = generate_codegraph(self.test_dir, self.output_json)
        
        # Verify that output JSON exists
        self.assertTrue(os.path.exists(self.output_json))
        
        # Read and parse the JSON data
        with open(self.output_json, "r") as f:
            graph_data = json.load(f)
            
        # Verify JSON keys are correct
        self.assertIn("nodes", graph_data)
        self.assertIn("edges", graph_data)
        self.assertIn("summary", graph_data)
        
        nodes = graph_data["nodes"]
        edges = graph_data["edges"]
        
        print("\nGenerated Nodes:")
        for node_id, node in nodes.items():
            print(f"  {node_id}: {node['kind']} (name: {node['name']})")
            
        print("\nGenerated Edges:")
        for edge in edges:
            print(f"  {edge['source']} -> {edge['target']} ({edge['kind']})")

        # Let's perform some basic structural assertions.
        # We expect main, main:compute, main:run, utils, utils:add, utils:subtract.
        # Let's check for standard components.
        self.assertTrue(any(node["kind"] == "module" and node["name"] == "main" for node in nodes.values()), "main module node missing")
        self.assertTrue(any(node["kind"] == "module" and node["name"] == "utils" for node in nodes.values()), "utils module node missing")
        
        # Check functions are captured
        self.assertIn("main:compute", nodes)
        self.assertIn("main:run", nodes)
        self.assertIn("utils:add", nodes)
        self.assertIn("utils:subtract", nodes)
        
        # Let's verify contains edges
        contains_edges = [(e["source"], e["target"]) for e in edges if e["kind"] == "contains"]
        self.assertIn(("main", "main:compute"), contains_edges)
        self.assertIn(("main", "main:run"), contains_edges)
        self.assertIn(("utils", "utils:add"), contains_edges)
        self.assertIn(("utils", "utils:subtract"), contains_edges)
        
        # Let's verify call edges.
        # We expect a call from main:run to main:compute, and main:compute to add (or utils:add).
        call_edges = [(e["source"], e["target"]) for e in edges if e["kind"] == "calls"]
        self.assertTrue(any(src == "main:run" and "compute" in tgt for src, tgt in call_edges), "main:run should call main:compute")
        self.assertTrue(any("compute" in src and "add" in tgt for src, tgt in call_edges), "main:compute should call add")

if __name__ == "__main__":
    unittest.main()
