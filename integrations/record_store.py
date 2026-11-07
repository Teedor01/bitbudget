import json
import os
import re
import tempfile
from abc import ABC, abstractmethod

from core.records import Record
from integrations.codec import record_from_json, record_to_json

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RecordStore(ABC):
    @abstractmethod
    def put(self, rec: Record) -> str: ...
    @abstractmethod
    def get(self, digest: str):  
        ...


class MemoryRecordStore(RecordStore):
    def __init__(self):
        self._d = {}

    def put(self, rec):
        self._d[rec.digest()] = rec
        return rec.digest()

    def get(self, digest):
        return self._d.get(digest)


class DirRecordStore(RecordStore):
    """One JSON file per record digest; atomic write via temp file + rename."""
    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _file(self, digest):
        if not _HEX64.match(digest):
            raise ValueError("bad digest")
        return os.path.join(self.path, digest + ".json")

    def put(self, rec):
        d = rec.digest()
        fd, tmp = tempfile.mkstemp(dir=self.path)
        with os.fdopen(fd, "w") as f:
            json.dump(record_to_json(rec), f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._file(d))
        return d

    def get(self, digest):
        try:
            with open(self._file(digest)) as f:
                return record_from_json(json.load(f))
        except FileNotFoundError:
            return None
