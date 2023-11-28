import React, { useState } from 'react';
import './App.css';
import { Axios } from 'axios';
import {
	initCrypto,
	KeyPairType,
	VirgilCrypto,
	VirgilKeyPair,
	VirgilPublicKey
} from 'virgil-crypto';
import {
	fido2Create,
	fido2Get
} from '@ownid/webauthn';


let test: VirgilCrypto;
let keys: VirgilKeyPair;
let serverKey: VirgilPublicKey;
const init = async () => {
	await initCrypto();
};

init()
	.then(() => {
		test = new VirgilCrypto({defaultKeyPairType: KeyPairType.ED25519});
		keys = test.generateKeys();
	});

const request = new Axios({
	baseURL: 'http://localhost:3002',
	transformRequest: (req) => JSON.stringify(req),
	transformResponse: (res) => JSON.parse(res),
	headers: {
		'Content-Type': 'application/json',
		'Access-Control-Allow-Origin': '*',
	},
	responseType: 'json',
});

function App() {
	const [ result, setResult ] = useState<any>(null);
	const [ isLogged, setIsLogged ] = useState(false);
	const [ userName, setUserName ] = useState<string>('');
	const postRequestBody = () => {
		console.log({name: 'Tester', password: 'Flexer'});
		const body = test.signThenEncrypt(JSON.stringify({
			name: 'Tester',
			password: 'Flexer'
		}), keys.privateKey, [ keys.publicKey, serverKey ])
			.toString('base64');
		console.log('Уходит на сервер:', body);
		request.post('/post', {data: body})
			.then((value) => {
				console.log('До дешифровки', value.data.data);
				const res = test.decryptThenVerify(value.data.data, keys.privateKey, [ keys.publicKey, serverKey ])
					.toString('utf-8');
				console.log(res);
				setResult(res);
			});
	};
	const postRequest = () => {
		request.post('/new-post')
			.then((value) => {
				console.log('До дешифровки', value.data.data);
				const res = test.decryptThenVerify(value.data.data, keys.privateKey, [ keys.publicKey, serverKey ])
					.toString('utf-8');
				console.log(res);
				setResult(res);
			});
	};
	const getRequest = () => {
		request.get('/')
			.then((value) => {
				console.log('До дешифровки', value.data.data);
				const res = test.decryptThenVerify(value.data.data, keys.privateKey, [ keys.publicKey, serverKey ])
					.toString('utf-8');
				console.log(res);
				setResult(res);
			});
	};

	const reg = () => {
		request.post('/register/start', {username: userName})
			.then(async (value) => {
				const data = await fido2Create(value.data.data, userName);
				request.post('/register/finish', data)
					.then((value) => {
						if (value) {
							alert('Successfully created using webAuthn');
						}
					});
			});
	};

	const log = () => {
		request.post('/login/start', {username: userName})
			.then(async (value) => {
				const temp = test.exportPublicKey(keys.publicKey)
					.toString('base64');
				serverKey = test.importPublicKey(value.data.data.serverKey);
				value.data.data.challenge = value.data.data.challenge + '_' + temp;
				const data = await fido2Get(value.data.data, userName);
				request.post('/login/finish', {data})
					.then((value: any) => {
						if (value.data.res) {
							setIsLogged(value.data.res);
							alert('Successfully authenticated using webAuthn');
						}
					});
			});
	};

	return (
		<div>
			{ !isLogged &&
				<div className="container">
					<input onChange={ (e) => setUserName(e.currentTarget.value) }/>
					<button onClick={ () => reg() }>Register!</button>
					<button onClick={ () => log() }>Login</button>
				</div>
			}
			{ isLogged &&
				<div className="container">
					<button onClick={ () => postRequestBody() }>Post request with body</button>
					<button onClick={ () => postRequest() }>Post request without body</button>
					<button onClick={ () => getRequest() }>Get request</button>
					<h2>Result after decrypt, check console for more</h2>
					<h3>{ result }</h3>
				</div>
			}
		</div>
	);
}

export default App;
