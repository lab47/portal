package portal

const approvalPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Portal certificate approval</title><style>
body { font: 16px system-ui,sans-serif; background: #f5f7fb; color: #17212e; margin: 0; }
main { max-width: 540px; margin: 10vh auto; padding: 32px; background: white; border-radius: 12px; box-shadow: 0 4px 24px #17212e18; }
h1 { font-size: 24px; } code { overflow-wrap: anywhere; } label { display: block; margin: 20px 0; }
input { box-sizing: border-box; width: 100%; margin-top: 6px; padding: 10px; }
button { background: #184ec6; color: white; border: 0; border-radius: 6px; padding: 12px 18px; cursor: pointer; font-size: 16px; }
#message { min-height: 24px; } @media(max-width: 600px) { main { margin: 0; border-radius: 0; min-height: 100vh; box-sizing: border-box; } }
</style></head><body><main>
<h1>Approve a Portal certificate</h1>
<p>Only approve if you initiated a certificate request on your device. Compare this SSH key fingerprint with your device:</p>
<p><code>FINGERPRINT</code></p>
<label>Enrollment token (only for your first passkey)<input id="token" type="password" autocomplete="off"></label>
<button id="approve">Approve with passkey</button><p id="message" role="status"></p>
</main><script>
const code = new URLSearchParams(location.search).get('code');
const message = document.getElementById('message');
document.getElementById('approve').onclick = async () => {
  try {
    message.textContent = 'Waiting for your passkey…';
    const start = await fetch('/ceremony/start', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, token: document.getElementById('token').value})
    });
    if (!start.ok) throw new Error('Could not start approval (HTTP ' + start.status + ')');
    const {kind, options} = await start.json();
    const credential = kind === 'register'
      ? await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey)})
      : await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)});
    const finish = await fetch('/ceremony/finish?code=' + encodeURIComponent(code), {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(credential.toJSON())
    });
    if (!finish.ok) throw new Error('Passkey approval failed (HTTP ' + finish.status + ')');
    message.textContent = 'Approved. Your device can now receive the certificate.';
    document.getElementById('approve').disabled = true;
  } catch (err) { message.textContent = err.message; }
};
</script></body></html>`
