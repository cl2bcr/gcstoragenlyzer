import click
import json
import logging
from . import reporter
from .analyzer import GCSAnalyzer
from . import presenter

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
LOGGER = logging.getLogger(__name__)


@click.group(context_settings=dict(help_option_names=['-h', '--help']),
             help="Comprehensive Security and Analysis Tool for GCS (Google Cloud Storage).")
def main():
    pass


@main.group(help="✅ Lists buckets or bucket contents.")
def list():
    pass


@list.command(name='buckets', help="Lists all accessible GCS buckets.")
@click.option('--json-output', is_flag=True, help='Output in JSON format.')
def list_buckets(json_output):
    try:
        analyzer = GCSAnalyzer()
        click.secho("🔍 Scanning accessible buckets...", fg='cyan')
        bucket_list = analyzer.list_accessible_buckets()
        if json_output:
            click.echo(json.dumps(bucket_list, indent=2))
        else:
            if not bucket_list:
                click.secho("❌ No accessible buckets found.", fg='red')
                return
            click.secho(f"✅ {len(bucket_list)} accessible buckets found:", fg='green')
            for name in bucket_list:
                click.echo(f"  📦 {name}")
    except Exception as e:
        LOGGER.error(f"Bucket listing failed: {e}")


@list.command(name='tree', help="Lists a bucket's content in a detailed tree structure.")
@click.option('--bucket', required=True, help='The bucket name to list contents.')
def list_tree(bucket):
    try:
        analyzer = GCSAnalyzer()
        click.secho(f"\n🌳 Content tree for '{bucket}':", fg='cyan', bold=True)
        analyzer.print_perfect_tree(bucket)
    except Exception as e:
        LOGGER.error(f"Tree structure creation error: {e}")


@main.group(help="🔥 Performs security and data scans on buckets.")
def scan():
    pass


@scan.command(name='expose', help="Scans for public access risks.")
@click.option('--bucket', help='Specific bucket name to scan.')
@click.option('--all', 'scan_all', is_flag=True, help='Scan ALL accessible buckets.')
@click.option('--output-format', type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text',
              help='Specify output format.')
@click.option('--output-file', help='Save report to the specified file (required for HTML/JSON).')
def scan_expose(bucket, scan_all, output_format, output_file):
    if not bucket and not scan_all:
        click.secho("Error: Please use --bucket <name> or --all.", fg='red')
        return
    try:
        analyzer = GCSAnalyzer()
        targets = [bucket] if bucket else analyzer.list_accessible_buckets()
        all_results = []
        for target_bucket in targets:
            click.secho(f"\n🔎 Scanning '{target_bucket}' for public access...", fg='cyan', bold=True)
            result = analyzer.scan_bucket(target_bucket)
            all_results.append(result)

            if output_format == 'text' and not output_file:
                presenter.print_expose_result(result, analyzer)

        final_result = all_results[0] if len(all_results) == 1 else all_results
        if output_format == 'json':
            json_output = json.dumps(final_result, indent=2, ensure_ascii=False)
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                click.secho(f"✅ JSON report successfully created: {output_file}", fg='green')
            else:
                click.echo(json_output)
        elif output_format == 'html':
            if not output_file: raise click.UsageError("For HTML format, --output-file is required.")
            reporter.generate_expose_html_report(final_result, output_file)

    except Exception as e:
        LOGGER.error(f"Public access scan error: {e}", exc_info=True)


@scan.command(name='sensitive', help="Scans file contents for sensitive data.")
@click.option('--bucket', required=True, help='Bucket name to scan.')
@click.option('--folder', 'folder_path', default='', help='Scan only the specified folder and subfolders.')
@click.option('--public', 'public_only', is_flag=True, help='Scan ONLY objects with public access.')
@click.option('--file-type', help="Scan only specified extensions (e.g., .log,.txt). 'all' for all.")
@click.option('--output-format', type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text',
              help='Specify output format.')
@click.option('--output-file', help='Save report to the specified file (required for HTML/JSON).')
@click.option('--no-mask', is_flag=True, help='Remove masking from found matches.')
@click.option('--exclude-gitleaks', is_flag=True, help='Disable Gitleaks integration (default: enabled).')
def scan_sensitive(bucket, folder_path, public_only, file_type, output_format, output_file, no_mask, exclude_gitleaks):
    try:
        analyzer = GCSAnalyzer()
        file_types_list = ['all'] if file_type and file_type.strip().lower() == 'all' else \
            [f".{ext.strip().lstrip('.')}" for ext in file_type.split(',')] if file_type else None

        use_gitleaks = not exclude_gitleaks

        result = analyzer.scan_folder_sensitive(
            bucket_name=bucket, folder_path=folder_path, public_only=public_only,
            file_types=file_types_list, no_mask=no_mask, use_gitleaks=use_gitleaks)

        if not result.get('findings'):
            click.secho("✅ Scan completed, no sensitive data found.", fg='green')
            return

        if output_format == 'text':
            presenter.print_sensitive_result(result)
        elif output_format == 'json':
            json_output = json.dumps(result, indent=2, ensure_ascii=False)
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                click.secho(f"✅ JSON report successfully created: {output_file}", fg='green')
            else:
                click.echo(json_output)
        elif output_format == 'html':
            if not output_file: raise click.UsageError("For HTML format, --output-file is required.")
            reporter.generate_sensitive_html_report(result, output_file)

    except Exception as e:
        LOGGER.error(f"Sensitive data scan failed: {e}", exc_info=True)


@scan.command(name='old', help="Finds objects older than the specified days (for cost/security).")
@click.option('--bucket', required=True, help='Bucket name to scan.')
@click.option('--folder', 'folder_path', default='', help='Scan only the specified folder and subfolders.')
@click.option('--day', required=True, type=int, help='Number of days old for objects to be listed.')
@click.option('--output-format', type=click.Choice(['text', 'json', 'html'], case_sensitive=False), default='text',
              help='Specify output format.')
@click.option('--output-file', help='Save report to the specified file (required for HTML/JSON).')
def scan_old(bucket, folder_path, day, output_format, output_file):
    try:
        analyzer = GCSAnalyzer()
        click.secho(f"\n🔎 Scanning for objects older than {day} days in '{bucket}/{folder_path or '(root)'}'...",
                    fg='cyan')

        result = analyzer.scan_old_objects(
            bucket_name=bucket, folder_path=folder_path, days_old=day)

        if not result.get('old_objects'):
            click.secho("✅ Scan completed, no old objects found.", fg='green')
            return

        if output_format == 'text':
            analyzer.print_old_objects_tree(bucket, result['old_objects'])
        elif output_format == 'json':
            json_output = json.dumps(result, indent=2, ensure_ascii=False, default=str)  # default=str for datetime
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                click.secho(f"✅ JSON report successfully created: {output_file}", fg='green')
            else:
                click.echo(json_output)
        elif output_format == 'html':
            if not output_file: raise click.UsageError("For HTML format, --output-file is required.")
            reporter.generate_old_html_report(result, output_file)

    except Exception as e:
        LOGGER.error(f"Old object scan failed: {e}", exc_info=True)


if __name__ == '__main__':
    main()