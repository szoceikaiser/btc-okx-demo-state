"""Reviewed bounded capsule. Authenticate before unpack; exclusive fresh restore."""
import hashlib
import io
import json
from pathlib import PurePosixPath
import stat
import zipfile
import os
from pathlib import Path

from private_envelope import PrivacyError

MANIFEST = 'CAPSULE-MANIFEST.json'
REVIEW = 'RUNTIME-REVIEW-MANIFEST.json'
MAX_TOTAL = 8 * 1024 * 1024
MAX_ZIP = 2 * 1024 * 1024
MAX_MEMBERS = 128

def validate_names(names):
    seen={}
    full=set(names)
    for name in names:
        if name not in (MANIFEST,REVIEW) and not valid_name(name):raise PrivacyError('privacy_capsule_members_invalid')
        p=PurePosixPath(name)
        for q in (p,*p.parents):
            if q.as_posix()=='.':continue
            n=q.as_posix();old=seen.setdefault(n.casefold(),n)
            if n!=old:raise PrivacyError('privacy_capsule_case_collision')
        if any(q.as_posix() in full for q in p.parents):raise PrivacyError('privacy_capsule_prefix_collision')

def reject_links(path):
    path=Path(path)
    for p in (path,*path.parents):
        if p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()):
            raise PrivacyError('privacy_restore_link')

def restore(files,source_manifest_raw,parent):
    """Caller supplies already authenticated/unpacked bytes; never reuse a target.

    A caller-owned ephemeral directory must be empty. Private files mode 0600,
    directories 0700, exclusive create, readback, no generic ZIP extraction.
    """
    import tempfile
    parent=Path(parent)
    reject_links(parent)
    if not parent.is_dir() or any(parent.iterdir()):raise PrivacyError('privacy_restore_parent_not_empty')
    if reviewed_pins(source_manifest_raw)!={n:dict(bytes=len(b),sha256=sha(b)) for n,b in sorted(files.items())}:
        raise PrivacyError('privacy_capsule_reviewed_members_changed')
    root=Path(tempfile.mkdtemp(prefix='runtime-',dir=parent));os.chmod(root,0o700)
    # Check all file/directory prefix collisions before the first file write.
    names=set(files)|{REVIEW}
    folded={n.casefold() for n in names}
    for n in names:
        if n!=REVIEW and not valid_name(n):raise PrivacyError('privacy_restore_path')
        if any(p.as_posix().casefold() in folded for p in PurePosixPath(n).parents if p.as_posix()!='.'):
            raise PrivacyError('privacy_restore_prefix_collision')
    for name,raw in [*sorted(files.items()),(REVIEW,source_manifest_raw)]:
        path=root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        reject_links(path)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        if path.read_bytes()!=raw:raise PrivacyError('privacy_restore_readback')
    return root


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def valid_name(name):
    if (not isinstance(name, str) or not name or len(name) > 180 or not name.isascii()
            or any(ord(c) < 32 or ord(c) == 127 for c in name) or '\\' in name
            or ':' in name or '\x00' in name or name in (MANIFEST, REVIEW)):
        return False
    p = PurePosixPath(name)
    return (not p.is_absolute() and p.as_posix() == name
            and all(part not in ('', '.', '..', '.git') and not part.endswith(('.', ' ')) for part in p.parts)
            and not any(part.split('.')[0].upper() in
                {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
                for part in p.parts))


def reviewed_pins(raw):
    if not isinstance(raw,bytes) or not 0 < len(raw) <= 32768:
        raise PrivacyError('privacy_capsule_source_pin_invalid')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError()
            result[key]=value
        return result
    try:
        value=json.loads(raw,object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value,dict) or not isinstance(value.get('files'),dict):raise ValueError()
        result={}
        for name,pin in value['files'].items():
            if not name.startswith('package/') or not valid_name(name[8:]):raise ValueError()
            if (not isinstance(pin,dict) or set(pin)!={'bytes','sha256'}
                    or type(pin['bytes']) is not int or not 0<=pin['bytes']<=MAX_TOTAL
                    or not isinstance(pin['sha256'],str) or len(pin['sha256'])!=64
                    or any(c not in '0123456789abcdef' for c in pin['sha256'])):raise ValueError()
            result[name[8:]]=pin
        return result
    except Exception:
        raise PrivacyError('privacy_capsule_source_pin_invalid') from None


def pack(files, source_manifest_raw):
    if (not isinstance(files, dict) or not 1 <= len(files) < MAX_MEMBERS
            or any(not valid_name(n) or not isinstance(b, bytes) for n,b in files.items())
            or len({n.casefold() for n in files}) != len(files)
            or sum(map(len, files.values())) > MAX_TOTAL):
        raise PrivacyError('privacy_capsule_members_invalid')
    validate_names(files)
    pins={n:dict(bytes=len(b),sha256=sha(b)) for n,b in sorted(files.items())}
    if reviewed_pins(source_manifest_raw)!=pins:
        raise PrivacyError('privacy_capsule_reviewed_members_changed')
    manifest = dict(schema='btc-private-capsule-v1', source_manifest_sha256=sha(source_manifest_raw),files=pins)
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name,raw in [(MANIFEST,canonical(manifest)),(REVIEW,source_manifest_raw),*sorted(files.items())]:
            info = zipfile.ZipInfo(name, date_time=(2026,1,1,0,0,0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    raw = out.getvalue()
    if len(raw) > MAX_ZIP:
        raise PrivacyError('privacy_capsule_zip_size_invalid')
    return raw


def unpack(raw, *, expected_source_manifest_sha256):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ZIP:
        raise PrivacyError('privacy_capsule_zip_size_invalid')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            rows = z.infolist()
            names = [r.filename for r in rows]
            validate_names(names)
            if (not 3 <= len(rows) <= MAX_MEMBERS or len(set(names)) != len(names)
                    or len({n.casefold() for n in names}) != len(names)
                    or names.count(MANIFEST) != 1 or names.count(REVIEW) != 1
                    or any(n not in (MANIFEST,REVIEW) and not valid_name(n) for n in names)
                    or any(r.is_dir() or stat.S_IFMT(r.external_attr >> 16) != stat.S_IFREG
                           or r.flag_bits & 1 or r.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                           for r in rows)
                    or any(r.file_size>32768 for r in rows if r.filename in (MANIFEST,REVIEW))
                    or sum(r.file_size for r in rows) > MAX_TOTAL + 65536):
                raise PrivacyError('privacy_capsule_archive_invalid')
            with z.open(MANIFEST) as f:manifest_raw=f.read(32769)
            if len(manifest_raw) > 32768:
                raise PrivacyError('privacy_capsule_manifest_invalid')
            # Canonical equality also rejects duplicate keys and extraneous whitespace.
            manifest = json.loads(manifest_raw)
            if (canonical(manifest) != manifest_raw or set(manifest) != {'schema','source_manifest_sha256','files'}
                    or manifest['schema'] != 'btc-private-capsule-v1'
                    or manifest['source_manifest_sha256'] != expected_source_manifest_sha256
                    or set(manifest['files']) != set(names) - {MANIFEST,REVIEW}):
                raise PrivacyError('privacy_capsule_manifest_invalid')
            with z.open(REVIEW) as f:review_raw=f.read(32769)
            if (sha(review_raw)!=expected_source_manifest_sha256
                    or reviewed_pins(review_raw)!=manifest['files']):
                raise PrivacyError('privacy_capsule_reviewed_members_changed')
            # Read each stream through a hard cap even if ZIP size fields lie.
            files={}
            used=0
            for n in manifest['files']:
                pin=manifest['files'][n]
                if type(pin.get('bytes')) is not int or not 0<=pin['bytes']<=MAX_TOTAL:raise PrivacyError('privacy_capsule_members_invalid')
                with z.open(n) as f:
                    b=f.read(min(pin['bytes']+1,MAX_TOTAL-used+1))
                    if len(b)!=pin['bytes'] or f.read(1):raise PrivacyError('privacy_capsule_members_invalid')
                used+=len(b);files[n]=b
            if sum(map(len, files.values())) > MAX_TOTAL:
                raise PrivacyError('privacy_capsule_members_invalid')
            if any(manifest['files'][n] != dict(bytes=len(b),sha256=sha(b)) for n,b in files.items()):
                raise PrivacyError('privacy_capsule_file_pin_mismatch')
            return files
    except PrivacyError:
        raise
    except Exception:
        raise PrivacyError('privacy_capsule_invalid') from None
