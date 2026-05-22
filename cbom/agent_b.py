import os
from trailmark.query.api import QueryEngine

def generate_codegraph(target_dir: str, output_path: str = "codegraph.json") -> QueryEngine:
    """
    Initializes the QueryEngine from trailmark.query.api,
    constructs the directed call graph of the targeted repository,
    and serializes the full graph to JSON, saving it to output_path.
    """
    if not os.path.exists(target_dir):
        raise ValueError(f"Target directory '{target_dir}' does not exist.")

    # 1. Initialize the QueryEngine from trailmark.query.api by calling QueryEngine.from_directory(target_dir, language="auto")
    print(f"Initializing QueryEngine for target directory: {target_dir}")
    engine = QueryEngine.from_directory(target_dir, language="auto")

    # 2. Construct the directed call graph of the targeted repository
    # This is done automatically by QueryEngine.from_directory, but we can print some stats.
    summary = engine.summary()
    print(f"Constructed call graph. Summary: {summary}")

    # 3. Serialize the full graph to JSON using engine.to_json() and save it to codegraph.json
    print(f"Serializing graph to {output_path}...")
    json_data = engine.to_json()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_data)
    print("Serialization completed successfully.")

    return engine

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    output = sys.argv[2] if len(sys.argv) > 2 else "codegraph.json"
    generate_codegraph(target, output)
