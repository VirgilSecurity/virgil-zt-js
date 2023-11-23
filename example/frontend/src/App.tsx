import React, {useEffect, useState} from 'react';
import logo from './logo.svg';
import './App.css';
import {Axios} from 'axios';
import {initCrypto, KeyPairType, VirgilCrypto, VirgilKeyPair, VirgilPublicKey} from 'virgil-crypto';
import {OwnID} from '@ownid/react';

let test: VirgilCrypto;
let keys: VirgilKeyPair;
let serverKey: VirgilPublicKey;
const init = async () => {
  await initCrypto()
}

init().then(() => {
  test = new VirgilCrypto({ defaultKeyPairType: KeyPairType.ED25519})
  keys = test.generateKeys();
});

const request = new Axios({
  baseURL: "http://localhost:3001",
  transformRequest: (req) => JSON.stringify(req),
  transformResponse: (res) => JSON.parse(res),
  headers: {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  },
  responseType: "json",
})

function App() {
  const [result, setResult] = useState<any>(null)
  const [userName, setUserName] = useState<string>('');
  const login = () => {
    request.post('/login', {
      key: test.exportPublicKey(keys.publicKey).toString('base64')
    }).then((value) => {
      serverKey = test.importPublicKey(value.data.key);
      setResult(value.data.key)
    })
  }
  const postRequestBody = () => {
    console.log({name: 'Tester', password: 'Flexer'})
    const body = test.signThenEncrypt(JSON.stringify({name: 'Tester', password: 'Flexer'}), keys.privateKey, [keys.publicKey, serverKey]).toString('base64')
    console.log('Уходит на сервер:', body)
    request.post('/post', {data : body}).then((value) => {
      console.log('До дешифровки', value.data.data)
      const res = test.decryptThenVerify(value.data.data, keys.privateKey, [keys.publicKey, serverKey]).toString('utf-8');
      console.log(res);
      setResult(res);
    })
  }
  const postRequest = () => {
    request.post('/new-post').then((value) => {
      console.log('До дешифровки', value.data.data)
      const res = test.decryptThenVerify(value.data.data, keys.privateKey, [keys.publicKey, serverKey]).toString('utf-8');
      console.log(res);
      setResult(res);
    })
  }
  const getRequest = () => {
    request.get('/').then((value) => {
      console.log('До дешифровки', value.data.data)
      const res = test.decryptThenVerify(value.data.data, keys.privateKey, [keys.publicKey, serverKey]).toString('utf-8');
      console.log(res);
      setResult(res);
    })
  }

  const passkeysLogin = async () => {
    await request.post('/login/start', {username: userName}).then(async (value) => {
        const data = await fido2Get(value, userName);
        await request.post('/login/finish', data).then((value) => {
          console.log(value);
        })
    })
  }
  return (
    <div className="container">
      <button onClick={() => login()}>Login</button>
      <button onClick={() => postRequestBody()}>Post request with body</button>
      <button onClick={() => postRequest()}>Post request without body</button>
      <button onClick={() => getRequest()}>Get request</button>
      <h2>Result after decrypt, check console for more</h2>
      <h3>{result}</h3>
    </div>
    </div>
  );
}

export default App;
