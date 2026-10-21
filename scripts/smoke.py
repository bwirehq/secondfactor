"""Exercise the deployed HTTPS Go primary-auth example and MFA service.
Never print authenticator secrets, codes, proofs, or the demo password.
"""
import base64, hashlib, hmac, http.cookiejar, json, pathlib, ssl, struct, time, urllib.request, urllib.error
root=pathlib.Path(__file__).resolve().parent.parent
ctx=ssl.create_default_context(cafile=str(root/'secrets/dev.crt'))
jar=http.cookiejar.CookieJar()
client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
def call(path,body=None):
 data=None if body is None else json.dumps(body).encode()
 request=urllib.request.Request('https://localhost:9443'+path,data=data,headers={'Origin':'https://localhost:9443','Content-Type':'application/json'})
 with client.open(request,timeout=15) as response:return json.load(response)
for _ in range(90):
 try:
  call('/login',{'password':(root/'secrets/demo-password').read_text().strip()});break
 except (OSError,urllib.error.HTTPError):time.sleep(1)
else:raise SystemExit('demo did not become available')
setup=call('/mfa/enroll',{})
def code(secret):
 key=base64.b32decode(secret+'='*((8-len(secret)%8)%8));digest=hmac.new(key,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();offset=digest[-1]&15
 return f'{(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000:06}'
confirmed=call('/mfa/confirm',{'code':code(setup['secret'])});assert len(confirmed['recovery_codes'])==10
assert 'verified' in call('/protected')['message'].lower()
# Confirmation consumes the TOTP step. Verify again only after the next period.
time.sleep(31-int(time.time())%30)
assert call('/mfa/verify',{'code':code(setup['secret'])})['verified']
assert len(call('/mfa/regenerate',{})['recovery_codes'])==10
try:call('/protected');raise AssertionError('invalidated proof accepted')
except urllib.error.HTTPError as e:assert e.code==403
assert call('/logout',{})['signed_out']
try:call('/protected');raise AssertionError('signed-out session accepted')
except urllib.error.HTTPError as e:assert e.code==401
print('PASS: primary login -> enrollment -> confirmation -> TOTP -> protected route -> regeneration -> logout')
