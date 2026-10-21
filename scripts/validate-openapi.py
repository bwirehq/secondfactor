from pathlib import Path
import yaml
from openapi_spec_validator import validate_spec
spec=yaml.safe_load(Path('docs/openapi.yaml').read_text())
validate_spec(spec)
print('PASS: OpenAPI 3 validation')
