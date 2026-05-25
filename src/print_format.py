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
    table.add_column("CVEs", style="red")
    
    for package_name, package_version, cves in package_cves:
        if cves:
            table.add_row(
                package_name, 
                package_version, 
                "\n".join(f"{cve}" for cve in cves)
            )
    
    console.print(table)

def print_capabilities(package_capabilities):
    table = Table(title="Package Capability Analysis", box=box.ROUNDED)
    table.add_column("File", style="cyan")
    table.add_column("Capabilities", style="magenta")
    
    danger_levels = {
        "CAPABILITY_EXEC": "red",
        "CAPABILITY_ARBITRARY_EXECUTION": "red bold",
        "CAPABILITY_NETWORK": "yellow",
        "CAPABILITY_SAFE": "green",
    }
    
    for file_path, capabilities in package_capabilities:
        colored_caps = []
        for cap in capabilities:
            color = danger_levels.get(cap, "white")
            colored_caps.append(f"[{color}]{cap}[/{color}]")
        table.add_row(file_path, "\n".join(f"• {c}" for c in colored_caps))
    
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
            branch.add(f"[red]Matches: {matches}[/red]")
        
        console.print(tree)