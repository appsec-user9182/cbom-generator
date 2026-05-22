import os
import json
import subprocess
import shutil
import zipfile
from trailmark.query.api import QueryEngine

def parse_cbom(cbom_path: str) -> list[dict]:
    """
    Parses CycloneDX cbom.json for cryptographic assets.
    Returns a list of dicts: [
        {"crypto_primitive": str, "file_path": str, "line_number": int}
    ]
    """
    with open(cbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    findings = []
    components = data.get("components", [])
    
    for comp in components:
        # Check if it's a cryptographic asset or has cryptoProperties
        is_crypto = comp.get("type") == "cryptographic-asset" or "cryptoProperties" in comp
        if not is_crypto:
            continue
            
        # Extract crypto_primitive
        crypto_primitive = None
        # Option 1: cryptoProperties.algorithmProperties.name
        crypto_primitive = comp.get("cryptoProperties", {}).get("algorithmProperties", {}).get("name")
        if not crypto_primitive:
            # Option 2: component name
            crypto_primitive = comp.get("name")
            
        if not crypto_primitive:
            crypto_primitive = "Unknown"
            
        # Extract occurrences
        occurrences = comp.get("evidence", {}).get("occurrences", [])
        if occurrences and isinstance(occurrences, list):
            for occ in occurrences:
                file_path = None
                line_number = None
                
                loc = occ.get("location")
                if isinstance(loc, str):
                    file_path = loc
                elif isinstance(loc, dict):
                    file_path = loc.get("file") or loc.get("filePath")
                    
                val = occ.get("line") or occ.get("lineNumber") or occ.get("line_number")
                if val is None and isinstance(loc, dict):
                    val = loc.get("line") or loc.get("lineNumber")
                if val is not None:
                    try:
                        line_number = int(val)
                    except (ValueError, TypeError):
                        pass
                        
                if file_path and line_number is not None:
                    findings.append({
                        "crypto_primitive": crypto_primitive,
                        "file_path": file_path,
                        "line_number": line_number
                    })
        else:
            # Fallback if no occurrences but direct properties exist
            file_path = None
            line_number = None
            properties = comp.get("properties", [])
            for prop in properties:
                name = prop.get("name", "").lower()
                val = prop.get("value")
                if name in ("file", "filepath", "file_path", "filename", "source_file"):
                    file_path = val
                elif name in ("line", "linenumber", "line_number"):
                    try:
                        line_number = int(val)
                    except (ValueError, TypeError):
                        pass
            if not file_path:
                file_path = comp.get("file") or comp.get("filePath") or comp.get("file_path")
            if line_number is None:
                val = comp.get("line") or comp.get("lineNumber") or comp.get("line_number")
                if val is not None:
                    try:
                        line_number = int(val)
                    except (ValueError, TypeError):
                        pass
            if file_path and line_number is not None:
                findings.append({
                    "crypto_primitive": crypto_primitive,
                    "file_path": file_path,
                    "line_number": line_number
                })
            
    return findings

def find_node_by_location(engine: QueryEngine, file: str, line: int) -> list:
    """
    Finds matching node(s) in engine._store._graph.nodes by normalizing the target file path
    and checking if the target line is within the node's start_line and end_line (inclusive).
    """
    target_abs = os.path.abspath(file)
    matched_nodes = []
    
    root_path = getattr(engine._store._graph, 'root_path', None)
    
    for node_id, node in engine._store._graph.nodes.items():
        if not node.location or not node.location.file_path:
            continue
            
        node_file = node.location.file_path
        possible_paths = [
            os.path.abspath(node_file)
        ]
        if root_path:
            possible_paths.append(os.path.abspath(os.path.join(root_path, node_file)))
            
        # Match if target matches any resolved path
        match = False
        for p in possible_paths:
            if p == target_abs:
                match = True
                break
                
        # Fallback relative match
        if not match:
            n_file = node_file.replace('\\', '/').strip('/')
            t_file = file.replace('\\', '/').strip('/')
            if n_file == t_file or n_file.endswith('/' + t_file) or t_file.endswith('/' + n_file):
                match = True
                
        if match:
            start = node.location.start_line
            end = node.location.end_line
            if start <= line <= end:
                matched_nodes.append(node)
                
    return matched_nodes

def map_node_path(engine: QueryEngine, path: list[str]) -> list[str]:
    """
    Maps each node ID along the path to its qualified ID or name.
    """
    mapped = []
    for nid in path:
        if nid in engine._store._graph.nodes:
            node = engine._store._graph.nodes[nid]
            mapped.append(node.id or node.name or nid)
        else:
            mapped.append(nid)
    return mapped

import tempfile

def compile_mermaid_to_svg(mermaid_text: str) -> str:
    """
    Compiles Mermaid flowchart code to SVG using the local node compiler executable.
    """
    # Create temporary directory inside the workspace safely to avoid collisions
    with tempfile.TemporaryDirectory(dir=".") as tmp_dir:
        in_file = os.path.join(tmp_dir, "input.mmd")
        out_file = os.path.join(tmp_dir, "output.svg")
        
        with open(in_file, "w", encoding="utf-8") as f:
            f.write(mermaid_text)
            
        # Prepend the standalone Node/Java binary paths to PATH
        env = os.environ.copy()
        local_paths = os.path.abspath("./.local/node/bin") + ":" + os.path.abspath("./.local/java/bin")
        env["PATH"] = f"{local_paths}:{env.get('PATH', '')}"
        
        mmdc_path = os.path.abspath("./node_modules/.bin/mmdc")
        
        cmd = [mmdc_path, "-i", in_file, "-o", out_file]
        
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
        if os.path.exists(out_file):
            with open(out_file, "r", encoding="utf-8") as f:
                svg_content = f.read()
            return svg_content
        else:
            raise RuntimeError(f"SVG was not generated. Output: {result.stdout}\nError: {result.stderr}")

def generate_visual_map(blast_radius: dict, unreachable: list, output_path: str):
    """
    Generates a premium offline visual_map.html containing embedded SVGs for each vulnerability path.
    """
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deterministic Blast Radius Map</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #0f172a;
            color: #f1f5f9;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 3rem;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 1.5rem;
        }
        h1 {
            font-size: 2.25rem;
            font-weight: 700;
            margin: 0 0 0.5rem 0;
            color: #f8fafc;
        }
        .subtitle {
            color: #94a3b8;
            font-size: 1.125rem;
            margin: 0;
        }
        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 1.5rem;
            color: #e2e8f0;
            border-left: 4px solid #3b82f6;
            padding-left: 0.75rem;
        }
        .card {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .vulnerability-name {
            font-size: 1.25rem;
            font-weight: 600;
            color: #f8fafc;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            margin: 0;
        }
        .badges {
            display: flex;
            gap: 0.5rem;
        }
        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            text-transform: uppercase;
        }
        .badge-danger {
            background-color: #ef4444;
            color: #ffffff;
        }
        .badge-warning {
            background-color: #f59e0b;
            color: #0f172a;
        }
        .badge-info {
            background-color: #3b82f6;
            color: #ffffff;
        }
        .meta-list {
            list-style: none;
            padding: 0;
            margin: 0 0 1.5rem 0;
            font-size: 0.875rem;
            color: #94a3b8;
        }
        .meta-list li {
            margin-bottom: 0.25rem;
        }
        .meta-list strong {
            color: #cbd5e1;
        }
        .diagram-box {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 0.5rem;
            padding: 1.5rem;
            display: flex;
            justify-content: center;
            overflow-x: auto;
        }
        .diagram-box svg {
            max-width: 100%;
            height: auto;
        }
        .unreachable-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }
        .unreachable-card {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            padding: 1rem;
            border-left: 4px solid #64748b;
        }
        .unreachable-title {
            font-size: 1rem;
            font-weight: 600;
            color: #cbd5e1;
            margin: 0 0 0.5rem 0;
        }
        .unreachable-meta {
            font-size: 0.875rem;
            color: #94a3b8;
            margin: 0;
        }
        .legend {
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
            background-color: #1e293b;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid #334155;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
        }
        .legend-color {
            width: 1.25rem;
            height: 1.25rem;
            border-radius: 0.25rem;
            border: 1px solid;
        }
        .color-entry {
            background-color: #f8d7da;
            border-color: #dc3545;
        }
        .color-internal {
            background-color: #fff3cd;
            border-color: #ffc107;
        }
        .color-flaw {
            background-color: #343a40;
            border-color: #343a40;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Deterministic Cryptographic Blast Radius Map</h1>
            <p class="subtitle">Visual representation of call chains leading to cryptographic assets</p>
        </header>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color color-entry"></div>
                <span>Public Entry Point</span>
            </div>
            <div class="legend-item">
                <div class="legend-color color-internal"></div>
                <span>Internal Execution Chain</span>
            </div>
            <div class="legend-item">
                <div class="legend-color color-flaw"></div>
                <span>Cryptographic Flaw Node (Dark Charcoal)</span>
            </div>
        </div>
        
        <div class="section-title">Vulnerable Execution Paths (Blast Radius)</div>
"""
    
    if not blast_radius:
        html_content += "<p>No vulnerable execution paths found with reachable entrypoints.</p>"
    else:
        for node_name, info in blast_radius.items():
            crypto_primitive = info.get("crypto_primitive", "Unknown")
            exact_location = info.get("exact_location", "Unknown")
            entrypoints = info.get("exposed_entrypoints", [])
            
            unique_nodes = set()
            edges = set()
            
            node_map = {}
            node_counter = 0
            
            for path in entrypoints:
                for node_id in path:
                    if node_id not in node_map:
                        node_map[node_id] = f"node_{node_counter}"
                        node_counter += 1
                    unique_nodes.add(node_id)
                
                for i in range(len(path) - 1):
                    edges.add((path[i], path[i+1]))
            
            mermaid_lines = ["graph TD"]
            for node_id in unique_nodes:
                safe_id = node_map[node_id]
                mermaid_lines.append(f'    {safe_id}["{node_id}"]')
                
            for u, v in edges:
                mermaid_lines.append(f"    {node_map[u]} --> {node_map[v]}")
                
            for node_id in unique_nodes:
                safe_id = node_map[node_id]
                if node_id == node_name:
                    # Cryptographic Flaw Node: Dark charcoal fill (#343a40), stark white text
                    mermaid_lines.append(f"    style {safe_id} fill:#343a40,stroke:#343a40,color:#ffffff,stroke-width:2px;")
                elif any(path[0] == node_id for path in entrypoints):
                    # Public Entry Point: Light red fill (#f8d7da), dark red stroke (#dc3545)
                    mermaid_lines.append(f"    style {safe_id} fill:#f8d7da,stroke:#dc3545,color:#000000,stroke-width:2px;")
                else:
                    # Internal Execution Chain: Soft amber fill (#fff3cd), amber stroke (#ffc107)
                    mermaid_lines.append(f"    style {safe_id} fill:#fff3cd,stroke:#ffc107,color:#000000,stroke-width:2px;")
            
            mermaid_text = "\n".join(mermaid_lines)
            
            try:
                svg_content = compile_mermaid_to_svg(mermaid_text)
            except Exception as e:
                svg_content = f"<pre>Error compiling Mermaid diagram: {str(e)}</pre>"
                
            html_content += f"""
        <div class="card">
            <div class="card-header">
                <h2 class="vulnerability-name">{node_name}</h2>
                <div class="badges">
                    <span class="badge badge-danger">Reachable</span>
                    <span class="badge badge-info">{crypto_primitive}</span>
                </div>
            </div>
            <ul class="meta-list">
                <li><strong>Cryptographic Primitive:</strong> {crypto_primitive}</li>
                <li><strong>Exact Location:</strong> {exact_location}</li>
                <li><strong>Number of Entrypoint Paths:</strong> {len(entrypoints)}</li>
            </ul>
            <div class="diagram-box">
                {svg_content}
            </div>
        </div>
"""
            
    html_content += """
        <div class="section-title">Unreachable/Static Library Imports</div>
        <div class="unreachable-grid">
"""
    if not unreachable:
        html_content += "<p>No unreachable cryptographic assets identified.</p>"
    else:
        for item in unreachable:
            crypto_primitive = item.get("crypto_primitive", "Unknown")
            exact_location = item.get("exact_location", "Unknown")
            html_content += f"""
            <div class="unreachable-card">
                <h3 class="unreachable-title">{crypto_primitive}</h3>
                <p class="unreachable-meta"><strong>Location:</strong> {exact_location}</p>
            </div>
"""
            
    html_content += """
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def package_to_zip(zip_path: str, files: list[str]):
    """
    Packages the list of files into a standalone ZIP archive.
    """
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            zipf.write(file, os.path.basename(file))

def populate_entrypoints_if_empty(engine: QueryEngine, target_dir: str = None):
    """
    Statically analyzes the call graph to identify public entry points (e.g. functions
    with 0 callers in routes, controllers, top-level files) and populates graph.entrypoints.
    """
    graph = engine._store._graph
    
    # If entrypoints are already present, do not overwrite
    if graph.entrypoints:
        return
        
    if target_dir is None:
        target_dir = getattr(graph, 'root_path', None) or "."
    target_dir_abs = os.path.abspath(target_dir)
    
    # Calculate callers for each node (case-insensitive)
    called_by = {node_id: [] for node_id in graph.nodes}
    
    for edge in graph.edges:
        source = getattr(edge, 'source_id', None)
        target = getattr(edge, 'target_id', None)
        kind_str = str(getattr(edge, 'kind', '')).lower()
        if source and target and "calls" in kind_str:
            if target in called_by:
                called_by[target].append(source)
                
    # Identify valid public entry points
    for node_id, callers in called_by.items():
        node = graph.nodes[node_id]
        node_kind = str(node.kind).lower()
        if "function" in node_kind or "method" in node_kind:
            if not callers:
                file_path = node.location.file_path if node.location else ""
                if not file_path:
                    continue
                    
                file_name = os.path.basename(file_path).lower()
                
                try:
                    rel_dir = os.path.dirname(os.path.relpath(file_path, target_dir_abs))
                except Exception:
                    rel_dir = ""
                    
                is_top_level = rel_dir == "" or rel_dir == "."
                is_entrypoint_file = any(pat in file_name for pat in ["route", "app", "main", "cli", "api", "controller", "handler"])
                is_entrypoint_func = any(pat in node.name.lower() for pat in ["main", "handler", "run", "handle"])
                
                if is_top_level or is_entrypoint_file or is_entrypoint_func:
                    graph.entrypoints[node_id] = True

def analyze_cbom(cbom_path: str, engine: QueryEngine = None, target_dir: str = None, output_dir: str = ".") -> dict:
    """
    Main entry point for Deterministic Junction Engine.
    Parses CycloneDX cbom.json, queries QueryEngine for reachability,
    saves output files blast_radius.json and visual_map.html,
    and packages them into a standalone ZIP file.
    """
    if engine is None:
        if target_dir is None:
            raise ValueError("Either engine or target_dir must be provided.")
        engine = QueryEngine.from_directory(target_dir, language="auto")
        
    # Populate entrypoints if none are detected dynamically
    populate_entrypoints_if_empty(engine, target_dir)
        
    findings = parse_cbom(cbom_path)
    
    blast_radius = {}
    unreachable = []
    
    for f in findings:
        primitive = f["crypto_primitive"]
        file_path = f["file_path"]
        line = f["line_number"]
        location_str = f"{file_path}:{line}"
        
        matched_nodes = find_node_by_location(engine, file_path, line)
        reachable_paths_found = False
        
        if matched_nodes:
            for node in matched_nodes:
                # Query engine._store.entrypoint_paths_to(node_id)
                paths = engine._store.entrypoint_paths_to(node.id)
                if paths:
                    reachable_paths_found = True
                    mapped_paths = []
                    for path in paths:
                        mapped_paths.append(map_node_path(engine, path))
                        
                    # Add to blast_radius
                    if node.id not in blast_radius:
                        blast_radius[node.id] = {
                            "crypto_primitive": primitive,
                            "exact_location": location_str,
                            "exposed_entrypoints": []
                        }
                    for p in mapped_paths:
                        if p not in blast_radius[node.id]["exposed_entrypoints"]:
                            blast_radius[node.id]["exposed_entrypoints"].append(p)
                            
        if not reachable_paths_found:
            unreachable.append({
                "crypto_primitive": primitive,
                "exact_location": location_str
            })
            
    # De-duplicate unreachable entries
    unique_unreachable = []
    seen = set()
    for item in unreachable:
        key = (item["crypto_primitive"], item["exact_location"])
        if key not in seen:
            seen.add(key)
            unique_unreachable.append(item)
            
    blast_radius_out = {
        **blast_radius,
        "Unreachable/Static Library Import": unique_unreachable
    }
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # 7. Generate blast_radius.json
    blast_radius_json_path = os.path.join(output_dir, "blast_radius.json")
    with open(blast_radius_json_path, "w", encoding="utf-8") as f_out:
        json.dump(blast_radius_out, f_out, indent=2)
        
    # 8. Generate visual_map.html
    visual_map_path = os.path.join(output_dir, "visual_map.html")
    generate_visual_map(blast_radius, unique_unreachable, visual_map_path)
    
    # 9. Package both into a standalone ZIP
    zip_path = os.path.join(output_dir, "blast_radius.zip")
    package_to_zip(zip_path, [blast_radius_json_path, visual_map_path])
    
    return blast_radius_out
