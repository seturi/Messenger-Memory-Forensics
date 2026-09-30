"""Merge Signal result CSVs across memory files without discarding provenance."""
import argparse
import csv
import json
from pathlib import Path
from uuid import UUID

try:
    from .signal_parser import FIELDS
    from .parser_io import write_csv, check_output
except ImportError:
    from signal_parser import FIELDS
    from parser_io import write_csv, check_output

CORE = ('message', 'conversation_id', 'sent_at_ms', 'message_type')
MERGED_FIELDS = ['source_file', 'parser'] + FIELDS + ['source_count', 'source_files_json', 'record_formats_json']


def merge_results(paths, output):
    groups = {}
    input_rows = 0
    for path in sorted({Path(p).resolve() for p in paths}):
        check_output(path, output)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            if not {'message_id', 'source_file', 'evidence_json'}.issubset(reader.fieldnames or []):
                raise ValueError(f'Not a Signal evidence CSV: {path}')
            for row in reader:
                key = str(UUID(row['message_id']))
                input_rows += 1
                variant = {field: row[field] for field in CORE}
                evidence = json.loads(row['evidence_json'])
                if not isinstance(evidence, list) or not evidence:
                    raise ValueError(f'Missing evidence for {key} in {path}')
                group = groups.setdefault(key, {'row': row, 'evidence': {}, 'conflicts': set()})
                group['conflicts'].update(filter(None, row.get('conflicting_fields', '').split('|')))
                for item in evidence:
                    item = dict(item)
                    item.setdefault('source_file', row['source_file'])
                    item.setdefault('process_id', row.get('process_id', ''))
                    item.setdefault('variant', variant)
                    # Normalize CSV strings and decoder numbers for comparison.
                    item['variant'] = {field: str(item['variant'][field]) for field in CORE}
                    identity = (item['source_file'].replace('\\', '/').casefold(),
                                int(item['offset'], 16), item['record_format'])
                    if identity in group['evidence'] and group['evidence'][identity] != item:
                        raise ValueError(f'Inconsistent evidence at {identity}')
                    group['evidence'][identity] = item
                if row['record_format'] == 'sqlite-record' and group['row']['record_format'] != 'sqlite-record':
                    group['row'] = row
    merged = []
    for key, group in groups.items():
        row = {field: group['row'].get(field, '') for field in ['source_file', 'parser'] + FIELDS}
        row['id'] = row['message_id'] = key
        evidence = list(group['evidence'].values())
        conflicts = group['conflicts']
        for field in CORE:
            if any(item['variant'][field] != str(row[field]) for item in evidence):
                conflicts.add(field)
        sources = sorted({item['source_file'] for item in evidence})
        row.update(occurrence_count=len(evidence), evidence_json=json.dumps(evidence, ensure_ascii=False),
                   conflicting_fields='|'.join(sorted(conflicts)), source_count=len(sources),
                   source_files_json=json.dumps(sources, ensure_ascii=False),
                   record_formats_json=json.dumps(sorted({item['record_format'] for item in evidence})))
        merged.append(row)
    merged.sort(key=lambda row: (int(row['sent_at_ms']), row['message_id']))
    count = write_csv(merged, MERGED_FIELDS, output)
    return dict(unique_messages=count, input_rows=input_rows,
                occurrences=sum(row['occurrence_count'] for row in merged),
                conflicting_messages=sum(bool(row['conflicting_fields']) for row in merged),
                output_file=str(Path(output).resolve()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('results_folder', type=Path)
    ap.add_argument('output_csv', type=Path)
    args = ap.parse_args()
    paths = list(args.results_folder.rglob('*.signal.csv'))
    if not paths:
        ap.error('No *.signal.csv files found')
    print(json.dumps(merge_results(paths, args.output_csv), ensure_ascii=False))


if __name__ == '__main__':
    main()
