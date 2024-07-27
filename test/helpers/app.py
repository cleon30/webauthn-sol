from multiprocessing import Process
import sys
from flask import Flask, render_template_string

_app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebAuthn Test with Flask</title>
</head>
<body>
    <h2>WebAuthn Test Page</h2>
    <button id="authButton">Authenticate with WebAuthn</button>
    <input type="text" id="challengeInput" value="fillme">
    <div id="assertionResult"></div>

    <script>
    var globalAssertion = null;
    var rpId = '';

    function setRpId(_rpId) {
        rpId = _rpId;
        console.log('rpId set to:', rpId);
    }

    function arrayBufferToBase64Sync(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function getClientDataJson() {
        const utf8Decoder = new TextDecoder('utf-8');
        const clientDataJson = utf8Decoder.decode(
            globalAssertion.response.clientDataJSON);
        return clientDataJson;
    }

    document.getElementById('authButton').addEventListener('click', async () => {
        try {
            const challengeInput = document.getElementById('challengeInput').value;
            console.log('Challenge:', challengeInput);
            console.log('rpId:', rpId);
            
            const challengeArray = new Uint8Array(challengeInput.split('').map(c => c.charCodeAt(0))).buffer;

            const options = {
                publicKey: {
                    challenge: challengeArray,
                    rpId: rpId,
                    userVerification: 'preferred',
                    allowCredentials: [{
                        id: Uint8Array.from("coinbase", c => c.charCodeAt(0)),
                        type: 'public-key',
                        transports: ['usb', 'ble', 'nfc'],
                    }],
                    timeout: 60000,
                }
            };
            
            console.log('Assertion options:', options);
            let assertion = await navigator.credentials.get(options);
            console.log('Assertion result:', assertion);
            globalAssertion = assertion;
            document.getElementById('assertionResult').textContent = 'Assertion completed successfully';
        } catch (error) {
            console.error('Error:', error);
            document.getElementById('assertionResult').textContent = 'Error: ' + error.message;
        }
    });
    </script>
</body>
</html>
'''

@_app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

def _start():
    _app.run(host="0.0.0.0", port=1234)

server = Process(target=_start)

def listen():
    server.start()

def shutdown():
    server.terminate()
    server.join()

if __name__ == "__main__":
    listen()