import json
import os


def diagnostics() -> str:
    return json.dumps(dict(os.environ))
