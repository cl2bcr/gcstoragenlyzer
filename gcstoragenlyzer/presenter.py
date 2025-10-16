import click
from typing import List, Dict
from datetime import timezone
from .analyzer import GCSAnalyzer

def print_sensitive_result(result: dict):
    findings = result.get('findings', [])
    bucket_name = result.get('bucket_name', 'N/A')
    folder_path = result.get('folder_path', 'N/A')

    click.secho(f"\n--- Sensitive Data Scan Results: {bucket_name}/{folder_path} ---", bold=True)
    if not findings:
        click.secho("✅ No findings detected.", fg='green')
        return

    click.secho(f"🚨 Total {len(findings)} potential findings detected:", fg='red', bold=True)

    current_object = ""
    for find in sorted(findings, key=lambda x: x['object']):
        if find['object'] != current_object:
            current_object = find['object']
            click.secho(f"\n📄 Object: {current_object}", fg='cyan')

        click.echo(
            f"  - 🏷️  Type: " +
            click.style(f"{find['pattern_name']}", bold=True) +
            f" | 🎭 Masked Value: " +
            click.style(f"{find['match_masked']}", fg='yellow')
        )


def print_expose_result(result: dict, analyzer: GCSAnalyzer):
    if result.get('error'):
        click.secho(f"Error: {result['error']}", fg='red')
        return

    summary = result.get('summary', {})
    status = summary.get('status', 'UNKNOWN')
    message = summary.get('message', 'No details found.')

    click.echo("\n" + "=" * 20 + " SCAN SUMMARY " + "=" * 20)
    if status == 'CRITICAL':
        click.secho(f"🚨 CRITICAL: {message}", fg='red', bold=True)
    elif status == 'WARNING':
        click.secho(f"⚠️  WARNING: {message}", fg='yellow', bold=True)
    elif status == 'SAFE':
        click.secho(f"✅ SAFE: {message}", fg='green')
    else:
        click.echo(message)
    click.echo("=" * 55 + "\n")

    if result.get('fine_grained') and result.get('folder_tree'):
        click.secho("Tree Structure (Fine-Grained - Object Level Control):", bold=True)
        analyzer.print_folder_tree_fine_grained([result['folder_tree']])

    elif result.get('uniform_access'):
        click.secho("Tree Structure (Uniform Access - Folder Level Control):", bold=True)

        root_objects_info = result.get('root_objects')
        folders = result.get('folders', [])

        if root_objects_info:
            is_public = root_objects_info.get('status') == 'PUBLIC'
            icon, color = ("🚨", "red") if is_public else ("✅", "green")

            for i, obj_name in enumerate(root_objects_info.get('objects', [])):
                is_last_item = i == len(root_objects_info['objects']) - 1 and not folders
                connector = "└── " if is_last_item else "├── "
                click.secho(f"{connector}{icon} {obj_name}", fg=color, bold=is_public)

        if folders:
            print_uniform_access_tree(folders)

        if not root_objects_info and not folders:
            click.echo("No objects or folders to display in the bucket.")

def print_uniform_access_tree(folders: List[Dict], indent: str = ""):
    for i, folder in enumerate(folders):
        is_last_folder = i == len(folders) - 1
        connector = "└── " if is_last_folder else "├── "
        child_indent = indent + ("    " if is_last_folder else "│   ")

        name = folder.get('name', 'N/A')
        is_public = folder.get('is_public', False)
        reason = folder.get('reason', '')
        objects = folder.get('objects', [])
        subfolders = folder.get('subfolders', [])

        icon, color = ("🚨", "red") if is_public else ("✅", "green")

        click.secho(f"{indent}{connector}{icon} {name}/", fg=color, bold=is_public, nl=False)
        click.secho(f" ({reason})", fg='bright_black')

        for j, obj_name in enumerate(objects):
            is_last_item_in_folder = j == len(objects) - 1 and not subfolders
            obj_connector = "└── " if is_last_item_in_folder else "├── "
            obj_icon = "📄"
            click.secho(f"{child_indent}{obj_connector}{obj_icon} {obj_name.split('/')[-1]}", fg=color, bold=is_public)

        if subfolders:
            print_uniform_access_tree(subfolders, child_indent)
