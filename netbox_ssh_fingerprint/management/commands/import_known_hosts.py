from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from utilities.request import apply_request_processors

from netbox_ssh_fingerprint.importer import apply_import, plan_import
from netbox_ssh_fingerprint.jobs import job_request


class Command(BaseCommand):
    help = 'Import a known_hosts file: match lines to devices and VMs and record their keys. Dry run by default.'

    def add_arguments(self, parser):
        parser.add_argument('file')
        parser.add_argument('--user', required=True, help='NetBox user the changes are logged under')
        parser.add_argument('--status', choices=('pending', 'active'), default='pending',
                            help='Status of new keys (keys that differ from an active key stay pending)')
        parser.add_argument('--apply', action='store_true', help='Import; without it only report')

    def handle(self, file, user, status, apply, **options):
        try:
            user = get_user_model().objects.get(username=user)
        except get_user_model().DoesNotExist:
            raise CommandError(f'No user "{user}"')
        with open(file, encoding='utf-8', errors='replace') as f:
            text = f.read()
        with apply_request_processors(job_request(user)):
            plan = plan_import(text, user)
            for key, count in plan.counts.items():
                self.stdout.write(f'{key:10} {count}')
            for lineno, patterns in plan.unmatched:
                self.stdout.write(f'no host   line {lineno}: {", ".join(patterns)}')
            for lineno, patterns, hosts in plan.ambiguous:
                self.stdout.write(f'ambiguous line {lineno}: {", ".join(patterns)} -> {", ".join(hosts)}')
            for lineno, error in plan.errors:
                self.stdout.write(f'error     line {lineno}: {error}')
            if not apply:
                self.stdout.write('Dry run; use --apply to import.')
                return
            created, errors = apply_import(plan, status)
            for lineno, error in errors:
                self.stdout.write(f'error     line {lineno}: {error}')
            self.stdout.write(self.style.SUCCESS(f'Imported {len(created)} host key(s)'))
