import logging
import os
import re
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone
import click
import requests
from dotenv import load_dotenv
from google.api_core.exceptions import Forbidden, GoogleAPIError, NotFound
from google.cloud import storage
import subprocess
import tempfile
import json

from . import sensitive_patterns as sps

LOGGER = logging.getLogger(__name__)

DEFAULT_EXCLUDED_EXTENSIONS: Set[str] = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.glb'}


class GCSAnalyzer:
    def __init__(self):
        dotenv_path = os.path.join(os.getcwd(), '.env')
        if os.path.exists(dotenv_path):
            load_dotenv(dotenv_path=dotenv_path)
        else:
            print(f"Warning: .env file not found in current directory: {os.getcwd()}")

        credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if not credentials_path or not os.path.exists(credentials_path):
            raise ValueError(
                f"Please set GOOGLE_APPLICATION_CREDENTIALS in .env file to the service account key path. "
                f"File path: {credentials_path or 'Undefined'}"
            )

        try:
            self.client = storage.Client()
            self._bucket_cache = {}
        except Exception as e:
            raise ValueError(f"Failed to create GCS Client: {e}")

    def scan_old_objects(self, bucket_name: str, folder_path: str, days_old: int) -> Dict:
        LOGGER.info(f"Scanning for objects older than {days_old} days in '{bucket_name}/{folder_path}'...")
        now_utc = datetime.now(timezone.utc)
        old_objects = []
        total_size_of_old_objects = 0
        try:
            blobs_iterator = self.client.list_blobs(bucket_name, prefix=folder_path)
            for blob in blobs_iterator:
                if blob.name.endswith('/') or not blob.time_created:
                    continue
                age = now_utc - blob.time_created
                if age.days >= days_old:
                    old_objects.append({
                        'name': blob.name,
                        'size': blob.size,
                        'created_at': blob.time_created,
                        'age_days': age.days
                    })
                    if blob.size:
                        total_size_of_old_objects += blob.size
            return {
                'bucket_name': bucket_name,
                'folder_path': folder_path,
                'days_old_threshold': days_old,
                'old_objects': sorted(old_objects, key=lambda x: x['created_at']),
                'total_count': len(old_objects),
                'total_size': total_size_of_old_objects
            }
        except Exception as e:
            raise ValueError(f"Error during old object scan: {e}")

    def is_public_iam_simple(self, policy) -> bool:
        for binding in policy.bindings:
            members = binding['members']
            public_members = [m for m in members if m in ['allUsers', 'allAuthenticatedUsers']]
            if public_members and 'storage.objectViewer' in binding['role']:
                return True
        return False

    def is_public_acl(self, blob) -> bool:
        try:
            for acl in blob.acl.all():
                if acl.role == 'READER' and acl.entity in ['allUsers', 'allAuthenticatedUsers']:
                    return True
        except:
            pass
        return False

    def _get_bucket(self, bucket_name: str) -> storage.Bucket:
        if bucket_name not in self._bucket_cache:
            self._bucket_cache[bucket_name] = self.client.bucket(bucket_name)
        return self._bucket_cache[bucket_name]

    def _is_object_public(self, bucket_name: str, object_name: str) -> bool:
        try:
            if self.check_public_access_http(bucket_name, object_name):
                return True

            bucket = self._get_bucket(bucket_name)
            blob = bucket.blob(object_name)
            blob.reload(projection='full')
            for entry in blob.acl:
                if entry['entity'] in ['allUsers', 'allAuthenticatedUsers']:
                    return True

            return False
        except Exception:
            return False

    def list_accessible_buckets(self) -> List[str]:
        try:
            all_buckets = [bucket.name for bucket in self.client.list_buckets()]
            accessible = []
            for name in all_buckets:
                try:
                    bucket = self.client.bucket(name)
                    bucket.get_iam_policy(requested_policy_version=3)
                    accessible.append(name)
                except Forbidden:
                    click.echo(f"Warning: No access to bucket {name}, skipping.")
                except Exception as e:
                    click.echo(f"Error: Access test for {name} failed: {e}")
            return accessible
        except Exception as e:
            raise ValueError(f"Bucket listing error: {e}")

    def _scan_object_for_patterns(self, bucket_name: str, object_name: str, patterns: dict,
                                  no_mask: bool = False, file_types: Optional[List[str]] = None,
                                  use_gitleaks: bool = False):
        _, ext = os.path.splitext(object_name)
        ext = ext.lower()

        if file_types:
            if 'all' not in file_types and ext not in file_types:
                return []
        elif ext in DEFAULT_EXCLUDED_EXTENSIONS:
            return []

        click.echo(f"   Scanning: {object_name}")

        findings = []
        try:
            bucket = self._get_bucket(bucket_name)
            content = self._download_blob_snippet(bucket, object_name)
            if not content:
                return findings

            for key, pdata in patterns.items():
                try:
                    rx = re.compile(pdata['regex'])
                except re.error as e:
                    click.echo(f"⚠️  Invalid regex for {key}: {e}")
                    continue

                for m in rx.finditer(content):
                    if m.groups():
                        candidate = next((g for g in reversed(m.groups()) if g), m.group(0))
                    else:
                        candidate = m.group(0)

                    candidate_str = candidate.strip()
                    validator_name = pdata.get('validator')

                    if validator_name:
                        validator_ok, validator_reason = sps.run_validator_by_name(validator_name, candidate_str)
                        if not validator_ok:
                            continue
                    else:
                        validator_ok = True
                        validator_reason = "Regex match sufficient"

                    masked = candidate_str if no_mask else (
                        candidate_str[:4] + "..." + candidate_str[-4:] if len(candidate_str) > 8 else "...")

                    findings.append({
                        'object': object_name,
                        'pattern_key': key,
                        'pattern_name': pdata.get('name', key),
                        'match_raw': candidate_str,
                        'match_masked': masked,
                        'validator': validator_name,
                        'validator_ok': validator_ok,
                        'validator_reason': validator_reason
                    })

            if use_gitleaks:
                try:
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                        temp_file.write(content)
                        temp_path = temp_file.name

                    cmd = ['gitleaks', 'detect', '--source', temp_path, '--no-git', '--report-format', 'json',
                           '--report-path', '-']
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    os.unlink(temp_path)

                    if process.returncode in [0, 1]:
                        if process.stdout.strip():
                            leaks = json.loads(process.stdout)
                            for leak in leaks:
                                masked_value = leak['Secret'][:4] + "..." + leak['Secret'][-4:] if len(
                                    leak['Secret']) > 8 else "..."
                                findings.append({
                                    'object': object_name,
                                    'pattern_key': 'Gitleaks',
                                    'pattern_name': 'Gitleaks Secret',
                                    'match_raw': leak['Secret'],
                                    'match_masked': masked_value if not no_mask else leak['Secret'],
                                    'validator': 'Gitleaks',
                                    'validator_ok': True,
                                    'validator_reason': f"Rule: {leak['Description']}, Line: {leak['StartLine']}"
                                })
                    else:
                        click.echo(f"⚠️ Gitleaks error (returncode {process.returncode}): {process.stderr}")

                except FileNotFoundError:
                    click.echo("⚠️ Gitleaks not found. Please install Gitleaks and add to PATH.")
                except json.JSONDecodeError as je:
                    click.echo(f"⚠️ Gitleaks JSON parse error: {je}. Stdout: {process.stdout}")
                except Exception as e:
                    click.echo(f"⚠️ Gitleaks integration error: {e}")

        except Exception as e:
            click.echo(f"⚠️  _scan_object_for_patterns error ({object_name}): {e}")

        return findings

    def scan_folder_sensitive(self, bucket_name: str, folder_path: str = '',
                              public_only: bool = False, file_types: Optional[List[str]] = None,
                              no_mask: bool = False, patterns_module=None, use_gitleaks: bool = False) -> Dict:
        if patterns_module is None:
            patterns_module = sps
        patterns = patterns_module.PATTERNS

        prefix = (folder_path or '').rstrip('/')
        if prefix: prefix += '/'

        results = {'bucket_name': bucket_name, 'folder_path': prefix, 'findings': []}
        LOGGER.info("Sensitive data scan starting: %s/%s", bucket_name, prefix or "(root)")
        if public_only: LOGGER.info("Mode: Only scan public objects.")
        if file_types: LOGGER.info("Filter: File types -> %s", file_types)
        if use_gitleaks: LOGGER.info("Gitleaks integration enabled.")

        try:
            all_blobs_iterator = self.client.list_blobs(bucket_name, prefix=prefix)

            for blob in all_blobs_iterator:
                if blob.name.endswith('/'): continue

                if public_only and not self._is_object_public(bucket_name, blob.name):
                    LOGGER.info("   -> Skipped (private object): %s", blob.name)
                    continue

                findings = self._scan_object_for_patterns(
                    bucket_name=bucket_name,
                    object_name=blob.name,
                    patterns=patterns,
                    file_types=file_types,
                    no_mask=no_mask,
                    use_gitleaks=use_gitleaks
                )
                if findings:
                    results['findings'].extend(findings)

        except GoogleAPIError as e:
            raise ValueError(f"Sensitive data scan API error: {e}")

        return results

    def _download_blob_snippet(self, bucket, blob_name, max_bytes=1024 * 1024):
        try:
            blob = bucket.blob(blob_name)

            blob.reload()

            if getattr(blob, "size", 0) > 5 * 1024 * 1024:  # Larger than 5 MB
                data = blob.download_as_bytes(start=0, end=max_bytes - 1)
                return data.decode('utf-8', errors='ignore')
            else:
                data = blob.download_as_bytes()
                return data.decode('utf-8', errors='ignore')
        except Exception as e:
            LOGGER.error(f"Error downloading/reading '{blob_name}': {e}")
            return None

    def _format_size(self, num_bytes: int) -> str:
        if num_bytes is None: return "N/A"
        if num_bytes < 1024: return f"{num_bytes} B"
        power = 1024
        n = 0
        power_labels = {0: ' B', 1: ' KB', 2: ' MB', 3: ' GB', 4: ' TB'}
        while num_bytes >= power and n < len(power_labels) - 1:
            num_bytes /= power
            n += 1
        return f"{num_bytes:.1f}{power_labels[n]}"

    def print_perfect_tree(self, bucket_name: str):
        try:
            bucket = self._get_bucket(bucket_name)
            summary = {"folders": 0, "files": 0, "total_size": 0}
            self._print_tree_recursive(bucket, prefix="", indent_str="", is_last=True, summary=summary)
            click.echo("\n" + "-" * 50)
            total_size_str = self._format_size(summary['total_size'])
            click.secho(
                f"📊 Summary: {summary['folders']} Folders, {summary['files']} Objects (Total Size: {total_size_str})",
                bold=True)
        except NotFound:
            raise ValueError(f"Bucket not found: {bucket_name}")
        except Forbidden:
            raise PermissionError(f"No access to bucket: {bucket_name}")

    def _print_tree_recursive(self, bucket: storage.Bucket, prefix: str, indent_str: str, is_last: bool, summary: dict):
        iterator = self.client.list_blobs(bucket, prefix=prefix, delimiter='/')
        blobs = [blob for blob in iterator if not blob.name.endswith('/')]
        prefixes = sorted(list(iterator.prefixes))

        items = blobs + prefixes
        total_items = len(items)

        for i, item in enumerate(items):
            is_current_last = i == total_items - 1
            line_char = "└── " if is_current_last else "├── "
            indent_char = "    " if is_current_last else "│   "

            if isinstance(item, storage.Blob):
                summary["files"] += 1
                if item.size: summary["total_size"] += item.size
                file_size = self._format_size(item.size)
                mod_time_str = "N/A"
                if item.updated:
                    mod_time_str = item.updated.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

                click.echo(f"{indent_str}{line_char}📄 {os.path.basename(item.name)}  ", nl=False)
                click.secho(f"({file_size}, {mod_time_str})", fg='bright_black')

            else:
                summary["folders"] += 1
                click.echo(f"{indent_str}{line_char}📁 {os.path.basename(item.rstrip('/'))}/")
                self._print_tree_recursive(bucket, item, indent_str + indent_char, is_current_last, summary)

    def print_old_objects_tree(self, bucket_name: str, old_objects: List[Dict]):
        try:
            bucket = self._get_bucket(bucket_name)
            summary = {"folders": 0, "files": 0, "total_size": 0}
            old_names = {obj['name'] for obj in old_objects}
            self._print_old_tree_recursive(bucket, prefix="", indent_str="", is_last=True, summary=summary,
                                           old_objects=old_objects, old_names=old_names)
            click.echo("\n" + "-" * 50)
            total_size_str = self._format_size(summary['total_size'])
            click.secho(
                f"📊 Summary: {summary['folders']} Folders, {summary['files']} Objects (Total Size: {total_size_str})",
                bold=True)
        except NotFound:
            raise ValueError(f"Bucket not found: {bucket_name}")
        except Forbidden:
            raise PermissionError(f"No access to bucket: {bucket_name}")

    def _print_old_tree_recursive(self, bucket: storage.Bucket, prefix: str, indent_str: str, is_last: bool,
                                  summary: dict, old_objects: List[Dict], old_names: Set[str]):
        iterator = self.client.list_blobs(bucket, prefix=prefix, delimiter='/')
        blobs = [blob for blob in iterator if not blob.name.endswith('/') and blob.name in old_names]
        prefixes = sorted([p for p in iterator.prefixes if any(o['name'].startswith(p) for o in old_objects)])

        items = blobs + prefixes
        total_items = len(items)

        for i, item in enumerate(items):
            is_current_last = i == total_items - 1
            line_char = "└── " if is_current_last else "├── "
            indent_char = "    " if is_current_last else "│   "

            if isinstance(item, storage.Blob):
                summary["files"] += 1
                if item.size: summary["total_size"] += item.size
                file_size = self._format_size(item.size)
                old_obj = next((o for o in old_objects if o['name'] == item.name), None)
                created_at_str = old_obj['created_at'].astimezone(timezone.utc).strftime(
                    '%Y-%m-%d %H:%M:%S') if old_obj and old_obj['created_at'] else 'N/A'
                age_days = old_obj['age_days'] if old_obj else 'N/A'

                click.echo(f"{indent_str}{line_char}📄 {os.path.basename(item.name)}  ", nl=False)
                click.secho(f"({file_size}, {created_at_str}, {age_days} days)", fg='yellow')

            else:
                summary["folders"] += 1
                click.echo(f"{indent_str}{line_char}📁 {os.path.basename(item.rstrip('/'))}/")
                self._print_old_tree_recursive(bucket, item, indent_str + indent_char, is_current_last, summary,
                                               old_objects, old_names)

    def print_folder_tree_fine_grained(self, folder_trees: List[Dict], indent: str = ""):
        for i, folder in enumerate(folder_trees):
            is_last_in_level = i == len(folder_trees) - 1
            connector = "└── " if is_last_in_level else "├── "
            child_indent = indent + ("    " if is_last_in_level else "│   ")

            path = folder.get('path', '').rstrip('/')
            name = path.split('/')[-1] if '/' in path else path or 'root'

            public_count = folder.get('public_object_count', 0)
            total_count = folder.get('total_object_count', 0)

            if public_count > 0:
                status_icon, color = "🚨", "yellow"
                status = f"MIXED ({public_count}/{total_count} public)"
            elif total_count > 0:
                status_icon, color = "✅", "green"
                status = f"SAFE ({total_count} objects)"
            else:
                status_icon, color = "📁", "blue"
                status = "Empty"

            click.secho(f"{indent}{connector} {status_icon} {name}/", fg=color, bold=True, nl=False)
            click.echo(f" - {status}")

            objects = folder.get('objects', [])
            if objects:
                for j, obj_info in enumerate(objects):
                    is_last_obj = j == len(objects) - 1
                    obj_connector = "└── " if is_last_obj else "├── "
                    obj_name = obj_info['name'].split('/')[-1]
                    is_public = obj_info['is_public']
                    obj_status_icon = "🚨" if is_public else "✅"
                    obj_color = 'red' if is_public else 'bright_black'
                    click.secho(f"{child_indent}{obj_connector} {obj_status_icon} {obj_name}", fg=obj_color)

            if folder.get('subfolders'):
                self.print_folder_tree_fine_grained(folder['subfolders'], child_indent)

    def list_objects(self, bucket_name: str, folder_path: str = '') -> List[str]:
        items = self._list_folders_and_objects_raw(bucket_name, folder_path)
        return [obj for obj in items['objects'] if obj.startswith(folder_path)]

    def _list_folders_and_objects_raw(self, bucket_name: str, prefix: str = '') -> Dict[str, list]:
        try:
            bucket = self.client.bucket(bucket_name)

            iterator = self.client.list_blobs(bucket, prefix=prefix, delimiter='/')
            blobs = list(iterator)

            folders = list(iterator.prefixes)
            objects = [blob.name for blob in blobs if not blob.name.endswith('/')]

            return {
                'folders': sorted(folders),
                'objects': sorted(objects)
            }

        except NotFound:
            raise ValueError(f"Bucket not found: {bucket_name}")
        except Forbidden:
            raise PermissionError(f"No access to bucket: {bucket_name}")
        except Exception as e:
            raise ValueError(f"Listing error: {e}")

    def check_public_access_http(self, bucket_name: str, path: str = '') -> bool:
        try:
            url = f"https://storage.googleapis.com/{bucket_name}"
            if path:
                url += f"/{path}"

            response = requests.head(url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def get_exposed_prefixes_from_iam(self, policy, bucket_name: str) -> Dict[str, List[Dict]]:
        exposed = {}

        for binding in policy.bindings:
            public_members = [m for m in binding.get('members', [])
                              if m in ['allUsers', 'allAuthenticatedUsers']]

            if not public_members:
                continue

            role = binding.get('role', '')
            if 'storage.objectViewer' not in role and 'storage.legacyObjectReader' not in role:
                continue

            condition = binding.get('condition')
            if not condition:
                exposed[''] = [{
                    'role': role,
                    'members': public_members,
                    'condition': 'No condition - bucket level public',
                    'is_recursive': True
                }]
                continue

            expr = condition.get('expression', '')
            prefix = self._extract_prefix_from_condition(expr, bucket_name)

            if prefix is not None:
                if prefix not in exposed:
                    exposed[prefix] = []

                exposed[prefix].append({
                    'role': role,
                    'members': public_members,
                    'condition': expr,
                    'is_recursive': '**' in expr
                })

        return exposed

    def _extract_prefix_from_condition(self, condition_expr: str, bucket_name: str) -> Optional[str]:
        match = re.search(
            rf'resource\.name\.startsWith\(["\']projects/_/buckets/{bucket_name}/objects/([^"\']+)["\']\)',
            condition_expr
        )
        if match:
            prefix = match.group(1)
            return prefix.rstrip('/')

        match = re.search(
            rf'resource\.name\.matches\(["\']projects/_/buckets/{bucket_name}/objects/([^"\']+)["\']\)',
            condition_expr
        )
        if match:
            prefix = match.group(1).replace('**', '').replace('*', '').rstrip('/')
            return prefix

        return None

    def scan_folder_recursive(
            self,
            bucket_name: str,
            folder_path: str,
            exposed_prefixes: Dict[str, List[Dict]],
            parent_is_public: bool = False
    ) -> Dict:
        clean_path = folder_path.rstrip('/')

        is_public = parent_is_public or (clean_path in exposed_prefixes) or self.check_public_access_http(bucket_name,
                                                                                                          clean_path + '/')

        result = {
            'path': folder_path,
            'name': clean_path.split('/')[-1] if '/' in clean_path else clean_path,
            'is_public': is_public,
            'reason': '',
            'subfolders': [],
            'objects': [],
            'object_count': 0,
            'objects_status': ''
        }

        if parent_is_public:
            result['reason'] = "Parent folder is public, so this folder is public"
            result['objects_status'] = "All objects PUBLIC (parent inheritance)"
        elif clean_path in exposed_prefixes:
            details = exposed_prefixes.get(clean_path, [])
            if details:
                result['reason'] = f"Direct public via IAM condition: {details[0]['role']}"
                result['objects_status'] = "All objects PUBLIC (IAM policy)"
        elif is_public:
            result['reason'] = "Detected public via HTTP access test"
            result['objects_status'] = "All objects PUBLIC (HTTP test)"
        else:
            result['reason'] = "Private (no IAM condition, HTTP test failed)"
            result['objects_status'] = "All objects PRIVATE"

        items = self._list_folders_and_objects_raw(bucket_name, prefix=folder_path)

        real_objects = items['objects']
        result['object_count'] = len(real_objects)
        result['objects'] = real_objects

        for subfolder in items['folders']:
            subfolder_relative = subfolder[len(folder_path):] if subfolder.startswith(folder_path) else subfolder
            if subfolder_relative and '/' not in subfolder_relative.rstrip('/'):
                subfolder_result = self.scan_folder_recursive(
                    bucket_name,
                    subfolder,
                    exposed_prefixes,
                    parent_is_public=is_public
                )
                result['subfolders'].append(subfolder_result)

        return result

    def scan_bucket_uniform_access(self, bucket_name: str) -> Dict:
        try:
            bucket = self.client.bucket(bucket_name)
            bucket.reload()

            try:
                is_uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
            except AttributeError:
                is_uniform = False

            if not is_uniform:
                return {
                    'error': 'This bucket is not in Uniform Access mode. Using fine-grained ACL.',
                    'bucket_name': bucket_name,
                    'uniform_access': False
                }

            policy = bucket.get_iam_policy(requested_policy_version=3)

            result = {
                'bucket_name': bucket_name,
                'uniform_access': True,
                'bucket_level_public': False,
                'folders': [],
                'summary': {}
            }

            exposed_prefixes = self.get_exposed_prefixes_from_iam(policy, bucket_name)
            bucket_public = '' in exposed_prefixes or self.check_public_access_http(bucket_name)

            if bucket_public:
                result['bucket_level_public'] = True
                result['summary'] = {
                    'status': 'CRITICAL',
                    'message': 'Bucket is completely PUBLIC! All folders and objects are exposed.',
                    'reason': "Detected via IAM Policy or HTTP test"
                }
                return result

            root_items = self._list_folders_and_objects_raw(bucket_name, prefix='')

            for folder in root_items['folders']:
                folder_result = self.scan_folder_recursive(
                    bucket_name,
                    folder,
                    exposed_prefixes,
                    parent_is_public=False
                )
                result['folders'].append(folder_result)

            real_root_objects = root_items['objects']
            if real_root_objects:
                root_public = '' in exposed_prefixes or self.check_public_access_http(bucket_name)
                result['root_objects'] = {
                    'count': len(real_root_objects),
                    'status': 'PUBLIC' if root_public else 'PRIVATE',
                    'objects': real_root_objects
                }
            public_folders = self._count_public_folders(result['folders'])
            total_folders = self._count_total_folders(result['folders'])

            result['summary'] = {
                'status': 'WARNING' if public_folders > 0 else 'SAFE',
                'total_folders': total_folders,
                'public_folders': public_folders,
                'message': f"{public_folders}/{total_folders} folders public" if public_folders > 0
                else "No folders are public"
            }

            return result

        except Forbidden:
            raise PermissionError(f"No access to {bucket_name}.")
        except NotFound:
            raise ValueError(f"{bucket_name} not found.")
        except Exception as e:
            raise ValueError(f"Scan error: {e}")

    def _count_public_folders(self, folders: List[Dict]) -> int:
        count = 0
        for folder in folders:
            if folder.get('is_public', False):
                count += 1
            count += self._count_public_folders(folder.get('subfolders', []))
        return count

    def _count_total_folders(self, folders: List[Dict]) -> int:
        count = len(folders)
        for folder in folders:
            count += self._count_total_folders(folder.get('subfolders', []))
        return count

    def scan_folder_uniform_access(self, bucket_name: str, folder_path: str) -> Dict:
        try:
            bucket = self.client.bucket(bucket_name)
            policy = bucket.get_iam_policy(requested_policy_version=3)
            exposed_prefixes = self.get_exposed_prefixes_from_iam(policy, bucket_name)
            folder_result = self.scan_folder_recursive(bucket_name, folder_path, exposed_prefixes)
            return folder_result
        except Exception as e:
            raise ValueError(f"Scan error: {e}")

    def build_fine_grained_tree(self, bucket_name: str, prefix: str = '') -> Dict:
        bucket = self.client.bucket(bucket_name)
        items = self._list_folders_and_objects_raw(bucket_name, prefix)

        result = {
            'path': prefix.rstrip('/') or 'root',
            'subfolders': [],
            'objects': [],
            'total_object_count': 0,
            'public_object_count': 0
        }

        for obj_name in items['objects']:
            try:
                blob = bucket.blob(obj_name)
                is_public = self.is_public_acl(blob) or self.check_public_access_http(bucket_name, obj_name)

                result['objects'].append({
                    'name': obj_name,
                    'is_public': is_public
                })

                result['total_object_count'] += 1
                if is_public:
                    result['public_object_count'] += 1

            except Exception as e:
                click.echo(f"⚠️  {obj_name} could not be checked: {e}")

        for subfolder in items['folders']:
            subfolder_result = self.build_fine_grained_tree(bucket_name, subfolder)
            result['subfolders'].append(subfolder_result)

            result['total_object_count'] += subfolder_result['total_object_count']
            result['public_object_count'] += subfolder_result['public_object_count']

        return result

    def scan_bucket_fine_grained_access(self, bucket_name: str) -> Dict:
        try:
            bucket = self.client.bucket(bucket_name)
            bucket.reload()

            is_uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
            if is_uniform:
                return {
                    'error': 'This bucket is not in Fine-Grained mode. Using Uniform Access.',
                    'bucket_name': bucket_name,
                    'uniform_access': True
                }

            result = {
                'bucket_name': bucket_name,
                'fine_grained': True,
                'bucket_level_public': False,
                'folder_tree': None,
                'summary': {}
            }

            policy = bucket.get_iam_policy(requested_policy_version=3)
            bucket_public = self.is_public_iam_simple(policy) or self.check_public_access_http(bucket_name)

            if bucket_public:
                result['bucket_level_public'] = True
                result['summary'] = {
                    'status': 'CRITICAL',
                    'message': 'Bucket is completely PUBLIC! All objects are exposed.',
                    'reason': 'Detected via IAM Policy or HTTP test'
                }
                return result

            click.echo("🔍 Scanning objects (checking each object individually)...")
            folder_tree = self.build_fine_grained_tree(bucket_name)
            result['folder_tree'] = folder_tree

            total_objects = folder_tree['total_object_count']
            public_objects = folder_tree['public_object_count']

            result['summary'] = {
                'status': 'WARNING' if public_objects > 0 else 'SAFE',
                'total_objects': total_objects,
                'public_objects': public_objects,
                'message': f"{public_objects}/{total_objects} objects public" if public_objects > 0
                else "No objects are public"
            }

            return result

        except Forbidden:
            raise PermissionError(f"No access to {bucket_name}.")
        except NotFound:
            raise ValueError(f"{bucket_name} not found.")
        except Exception as e:
            raise ValueError(f"Scan error: {e}")

    def scan_bucket(self, bucket_name: str, folder_path: str = '') -> Dict:
        try:
            bucket = self.client.bucket(bucket_name)
            bucket.reload()

            is_uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled

            if folder_path:
                folder_path = folder_path.rstrip('/') + '/'

                if is_uniform:
                    result = self.scan_folder_uniform_access(bucket_name, folder_path)
                    return {
                        'bucket_name': bucket_name,
                        'folder_path': folder_path,
                        'uniform_access': True,
                        'folder_data': result,
                        'summary': {
                            'status': 'WARNING' if result.get('is_public', False) else 'SAFE',
                            'message': f"Folder {'PUBLIC' if result.get('is_public', False) else 'PRIVATE'}"
                        }
                    }
                else:
                    click.echo("🔍 Scanning objects (checking each object individually)...")
                    folder_tree = self.build_fine_grained_tree(bucket_name, folder_path)

                    total_objects = folder_tree['total_object_count']
                    public_objects = folder_tree['public_object_count']

                    return {
                        'bucket_name': bucket_name,
                        'folder_path': folder_path,
                        'fine_grained': True,
                        'folder_tree': folder_tree,
                        'summary': {
                            'status': 'WARNING' if public_objects > 0 else 'SAFE',
                            'total_objects': total_objects,
                            'public_objects': public_objects,
                            'message': f"{public_objects}/{total_objects} objects public" if public_objects > 0
                            else "No objects are public"
                        }
                    }
            else:
                if is_uniform:
                    return self.scan_bucket_uniform_access(bucket_name)
                else:
                    return self.scan_bucket_fine_grained_access(bucket_name)

        except Forbidden:
            raise PermissionError(f"No access to {bucket_name}.")
        except NotFound:
            raise ValueError(f"{bucket_name} not found.")
        except Exception as e:
            raise ValueError(f"Scan error: {e}")