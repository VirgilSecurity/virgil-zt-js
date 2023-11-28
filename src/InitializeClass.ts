import {
	initCrypto,
	VirgilCrypto
} from 'virgil-crypto';
import {
	CryptoKeys,
	Settings,
	User
} from './interfaces';
import {
	Request,
	Response
} from 'express';
import { NodeBuffer } from '@virgilsecurity/data-utils';
import { VirgilPublicKey } from 'virgil-crypto/dist/types/VirgilPublicKey';
import {
	verifyAuthenticationResponse,
	verifyRegistrationResponse
} from '@simplewebauthn/server';
import {
	getRegistrationInfo,
	getSavedAuthenticatorData
} from './functions';
import base64url from 'base64url';


class ZtMiddleware {

	private encryptKeys: CryptoKeys;
	private virgilCrypto: VirgilCrypto;
	private frontendPublicKey: VirgilPublicKey;
	private loginPath: string;
	private registerPath: string;
	private encryptEncoding: BufferEncoding;
	private storageControl: CallableFunction;
	private activeStorage = false;


	//Passkeys Flow variables
	private passkeysActive: boolean;
	private challenges: Map<string, string> = new Map();
	private prId: string;
	private origin: string[];
	private users: Map<string, User> = new Map();

	/*
		Initialize crypto module to upload wasm and other files
	 */
	private static initializeCryptoModule = async () => {
		await initCrypto();
	};

	constructor(settings: Settings) {
		ZtMiddleware.initializeCryptoModule()
			.then(() => {
				const {
					replayingId,
					expectedOrigin,
					registerPath,
					loginPath,
					keyType,
					encoding = 'base64',
					storageControl
				} = settings;
				this.prId = replayingId ?? '';
				this.origin = expectedOrigin ?? '';
				this.registerPath = registerPath;
				this.loginPath = loginPath;
				this.virgilCrypto = new VirgilCrypto({defaultKeyPairType: keyType});
				this.encryptKeys = this.virgilCrypto.generateKeys();
				this.loginPath = loginPath;
				this.encryptEncoding = encoding;
				if (storageControl) {
					this.storageControl = storageControl;
					const serverKeys = this.storageControl(false, false);
					if (serverKeys) {
						this.encryptKeys = serverKeys;
					} else {
						this.storageControl(true, false, this.encryptKeys);
					}
					this.activeStorage = true;
				}
				console.log('Successfully init Crypto Module');
			});
	}

	private encrypt(data: string): string {
		return this.virgilCrypto.signThenEncrypt(data, this.encryptKeys.privateKey, [ this.encryptKeys.publicKey, this.frontendPublicKey ])
			.toString(this.encryptEncoding);
	}

	private decrypt(data: string): string {
		return this.virgilCrypto.decryptThenVerify(data, this.encryptKeys.privateKey, [ this.encryptKeys.publicKey, this.frontendPublicKey ])
			.toString('utf-8');
	}

	private setKey(key: string): void {
		if (this.activeStorage) {
			const getKey = this.storageControl(false, true);
			if (getKey) {
				this.frontendPublicKey = this.virgilCrypto.importPublicKey(NodeBuffer.from(getKey, 'base64'));
			} else {
				this.storageControl(true, true, key);
				this.frontendPublicKey = this.virgilCrypto.importPublicKey(NodeBuffer.from(key, 'base64'));
			}
			return;
		}
		this.frontendPublicKey = this.virgilCrypto.importPublicKey(NodeBuffer.from(key, 'base64'));
	}

	private rewriteResponse(res: Response, pubKey?: unknown) {
		const oldJson = res.json;
		res.json = (body) => {
			res.locals.body = body;
			if (this.passkeysActive) {
				body = {data: pubKey};
			} else {
				body = {data: this.encrypt(typeof (body.data) === 'string' ? body.data : JSON.stringify(body.data))};
			}
			return oldJson.call(res, body);
		};
	}

	private postFlow(req: Request, res: Response) {
		if (req.body.data) {
			req.body.data = JSON.parse(this.decrypt(req.body.data));
		}
		this.rewriteResponse(res);
	}

	private defaultFlow(res: Response) {
		this.rewriteResponse(res);
	}

	private getNewChallenge(): string {
		return Math.random()
			.toString(36)
			.substring(2);
	}

	private convertChallenge(challenge: string) {
		return btoa(challenge)
			.replaceAll('=', '');
	}

	private async loginFlow(req: Request, res: Response, next: CallableFunction) {
		switch (req.url) {
		case this.registerPath + '/start': {
			const username = req.body.username;
			const challenge = this.getNewChallenge();
			const newId = this.users.size + 1;
			this.challenges.set(username, this.convertChallenge(challenge));
			const pubKey = {
				challenge: challenge,
				rp: {id: this.prId, name: 'webauthn-app'},
				user: {id: newId, name: username, displayName: username},
				pubKeyCredParams: [
					{type: 'public-key', alg: -7},
					{type: 'public-key', alg: -257},
				],
				authenticatorSelection: {
					authenticatorAttachment: 'cross-platform',
					userVerification: 'discouraged',
					residentKey: 'discouraged',
					requireResidentKey: false,
				}
			};
			res.send({data: pubKey});
			res.status(200);
			return next();
		}
		case this.registerPath + '/finish': {
			const username = req.body.username;
			await verifyRegistrationResponse({
				response: req.body.data,
				expectedChallenge: this.challenges.get(username)!,
				expectedOrigin: this.origin
			})
				.then((result) => {
					const {verified, registrationInfo} = result;
					if (verified) {
						this.users.set(username, getRegistrationInfo(registrationInfo));
						res.send({data: verified});
						res.status(200);
						return next();
					}
				})
				.catch((error) => {
					console.error(error);
					res.status(400);
					return next();
				});
			res.status(500);
			return next();
		}
		case this.loginPath + '/start': {
			const username = req.body.username;
			if (!this.users.get(username)) {
				res.status(404);
				return next();
			}
			const challenge = this.getNewChallenge();
			this.challenges.set(username, this.convertChallenge(challenge));
			res.send({
				data: {
					challenge,
					rpId: this.prId,
					allowCredentials: [ {
						type: 'public-key',
						id: this.users.get(username)!.credentialID,
						transports: [ 'external' ],
					} ],
					userVerification: 'discouraged',
					serverKey: this.virgilCrypto.exportPublicKey(this.encryptKeys.publicKey)
						.toString('base64')
				}
			});
			res.status(200);
			return next();
		}
		case this.loginPath + '/finish': {
			const username = req.body.data.username;
			if (!this.users.get(username)) {
				return res.status(404)
					.send(false);
			}
			const user = this.users.get(username);
			const clientInfoObj = JSON.parse(base64url.decode(req.body.data.data.response.clientDataJSON));
			const concatChallenge = base64url.decode(clientInfoObj.challenge);
			const key = concatChallenge.slice(concatChallenge.indexOf('_') + 1);
			this.setKey(key);
			await verifyAuthenticationResponse({
				expectedChallenge: base64url(base64url.decode(this.challenges.get(username)!) + '_' + key),
				response: req.body.data.data,
				authenticator: getSavedAuthenticatorData(user),
				expectedRPID: this.prId,
				expectedOrigin: this.origin
			})
				.then((result) => {
					const {verified} = result;
					res.send({res: verified});
					res.status(200);
					return next();
				})
				.catch((error) => {
					console.error(error);
					res.status(400);
					return next();
				});
			res.status(500);
			return next();
		}
		default:
			return next();
		}
	}

	public zeroTrustMiddleware = async (req: Request, res: Response, next: CallableFunction) => {
		if ((req.url.split('/')
			.includes(this.loginPath.slice(1)) || req.url.split('/')
			.includes(this.registerPath.slice(1))) && req.method === 'POST') {
			return this.loginFlow(req, res, next);
		}
		if (req.method === 'POST' || req.method === 'PUT') {
			this.postFlow(req, res);
			return next();
		}
		this.defaultFlow(res);
		return next();
	};

}


export {
	ZtMiddleware
};
