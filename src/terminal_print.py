from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()

def print_cves(package_cves):
    if not package_cves:
        console.print("[green]No CVEs found[/green]")
        return
    
    table = Table(title="Vulnerability Report", box=box.ROUNDED)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="white")
    table.add_column("CVEs / GHSAs", style="red")
    
    for package_name, package_version, go_vulns in package_cves:
        if go_vulns:
            
            go_vuln_lines = []
            for go_vuln in go_vulns:
                go_id = go_vuln["go_id"]
                aliases = go_vuln["aliases"]
                # If there are aliases (CVE/GHSA), show them first
                if aliases:
                    alias_str = ", ".join(aliases)
                    go_vuln_lines.append(f"* {alias_str}")
                    go_vuln_lines.append(f"[dim]({go_id})[/dim]")
                # If no aliases, just have the Go vulnerability
                else:
                    go_vuln_lines.append(f"* {go_id}")

            table.add_row(
                package_name, 
                package_version, 
                "\n".join(go_vuln_lines)
            )
    
    console.print(table)

def print_capabilities(package_capabilities):
    table = Table(title="Package Capability Analysis", box=box.ROUNDED)
    table.add_column("File", style="cyan")
    table.add_column("Package", style="bold")
    table.add_column("Capabilities", style="magenta")
    
    danger_levels = {
        "CAPABILITY_SAFE": "green",
        
        "CAPABILITY_READ_SYSTEM_STATE": "blue",
        "CAPABILITY_UNSPECIFIED": "white",
        "CAPABILITY_UNANALYZED": "white",

        "CAPABILITY_FILES": "yellow",
        "CAPABILITY_RUNTIME": "yellow",
        "CAPABILITY_REFLECT": "yellow",
        "CAPABILITY_CGO": "yellow",
        "CAPABILITY_UNSAFE_POINTER": "yellow",
        
        "CAPABILITY_NETWORK": "orange1",
        "CAPABILITY_MODIFY_SYSTEM_STATE": "orange1",
        "CAPABILITY_OPERATING_SYSTEM": "orange1",
        "CAPABILITY_SYSTEM_CALLS": "orange1",
        
        "CAPABILITY_EXEC": "red",
        "CAPABILITY_ARBITRARY_EXECUTION": "red",
    }
    
    for file_path, capabilities in package_capabilities:
        for package, capability in capabilities:
            color = danger_levels.get(capability, "white")
            table.add_row(
                file_path,
                package,
                f"[{color}]{capability}[/{color}]"
            )
    
    console.print(table)

def print_string_analysis(string_analysis):
    for file_path, findings in string_analysis:
        if not findings:
            continue
        
        tree = Tree(f"[cyan]{file_path}[/cyan]")
        for finding in findings:
            match_type = finding["type"]
            value = finding.get("decoded", finding["value"])
            matches = ", ".join(finding["matches"])
            
            branch = tree.add(f"[yellow]{match_type}[/yellow]: {value[:80]}...")
            branch.add(f"Matches: [red]{matches}[/red]")
        
        console.print(tree)