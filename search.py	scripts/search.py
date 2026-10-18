"""Search public YouTube videos using yt-dlp; return bounded JSON without downloading media."""
import argparse
import json
from pathlib import Path
import re
import sys
import unicodedata


def validate(inputs):
    job_id = str(inputs.get('job_id', ''))
    query = ' '.join(str(inputs.get('query', '')).split())
    limit = int(inputs.get('limit', 10))
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,80}', job_id):
        raise ValueError('Invalid job ID')
    if not 2 <= len(query) <= 160 or any(unicodedata.category(c) == 'Cc' for c in query):
        raise ValueError('Search query must contain 2 to 160 characters')
    if not 1 <= limit <= 20:
        raise ValueError('Search result limit must be between 1 and 20')
    return {'job_id': job_id, 'query': query, 'limit': limit}


def normalize(entries, limit):
    out, seen = [], set()
    for item in entries or []:
        if not isinstance(item, dict):
            continue
        video_id = str(item.get('id', ''))
        if not re.fullmatch(r'[A-Za-z0-9_-]{11}', video_id) or video_id in seen:
            continue
        seen.add(video_id)
        duration = item.get('duration')
        out.append({'id': video_id, 'url': 'https://www.youtube.com/watch?v=' + video_id,
                    'title': str(item.get('title') or 'YouTube video')[:240],
                    'channel': str(item.get('channel') or item.get('uploader') or '')[:140],
                    'duration': int(duration) if isinstance(duration, (int, float)) and 0 <= duration < 1e9 else None})
        if len(out) >= limit:
            break
    return out


def search(cfg, factory=None):
    if factory is None:
        from yt_dlp import YoutubeDL
        factory = YoutubeDL
    # The query is data in the ytsearch extractor, never a shell command or an arbitrary URL.
    options = {'extract_flat': True, 'skip_download': True, 'quiet': True, 'no_warnings': True,
               'ignoreerrors': False, 'socket_timeout': 25, 'retries': 2, 'extractor_retries': 2,
               'playlistend': cfg['limit'], 'cachedir': False}
    with factory(options) as downloader:
        result = downloader.extract_info('ytsearch' + str(cfg['limit']) + ':' + cfg['query'], download=False)
    if not isinstance(result, dict):
        raise ValueError('No search response')
    return normalize(result.get('entries'), cfg['limit'])


def main(argv=None, factory=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--event', required=True)
    parser.add_argument('--output', default='search-output')
    args = parser.parse_args(argv)
    inputs = json.loads(Path(args.event).read_text(encoding='utf-8')).get('inputs', {})
    cfg = validate(inputs)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    result = {'v': 1, 'job_id': cfg['job_id'], 'query': cfg['query'], 'entries': [], 'error': None}
    code = 0
    try:
        result['entries'] = search(cfg, factory)
    except Exception:
        result['error'] = 'החיפוש ביוטיוב לא הצליח בשרת. בדקי את יומן הריצה ונסי שוב מאוחר יותר.'
        code = 1
    (output / 'results.json').write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
    print('Search completed: ' + str(len(result['entries'])) + ' results' if not code else 'Search failed; result report was saved.')
    return code


if __name__ == '__main__':
    sys.exit(main())
