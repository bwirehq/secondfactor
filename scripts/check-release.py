"""Fail candidate CI if source includes forbidden project branding or secret files."""
import pathlib, subprocess, re
files=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')
for name in filter(None,files):
 p=pathlib.Path(name)
 assert not name.startswith('secrets/'), 'secret directory tracked'
 assert name!='.env', 'live environment tracked'
 if p.suffix in {'.go','.ts','.rs','.md','.yaml','.json','.sql'}:
  text=p.read_text()
  forbidden='king'+'ftp'
  assert forbidden not in text.lower(), 'unrelated application branding found'
print('PASS: candidate file hygiene')
