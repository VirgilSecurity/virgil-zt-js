import {
	initCrypto,
	VirgilCrypto
} from 'virgil-crypto';
import {
	CryptoKeys,
	Settings
} from './interfaces';
import {
	Request,
	Response
} from 'express';
import {NodeBuffer} from '@virgilsecurity/data-utils';
import {VirgilPublicKey} from 'virgil-crypto/dist/types/VirgilPublicKey';
import {
	verifyAuthenticationResponse,
	verifyRegistrationResponse
} from '@simplewebauthn/server';
import {
	getRegistrationInfo,
	getSavedAuthenticatorData
} from './functions';


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
	private origin: string;
	private users: Map<string, unknown> = new Map();

	/*
		Initialize crypto module to upload wasm and other files
	 */
	private static initializeCryptoModule = async () => {
		await initCrypto();
	};

	private noPasskeysFlowSetup = ({keyType, loginPath, encoding = 'base64', storageControl}: Settings) => {
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
	};

	constructor(settings: Settings) {
		ZtMiddleware.initializeCryptoModule()
			.then(() => {
				if (settings.passkeyFlow) {
					const {passkeyFlow, replayingId, expectedOrigin, registerPath, loginPath} = settings;
					this.passkeysActive = passkeyFlow;
					this.prId = replayingId ?? '';
					this.origin = expectedOrigin ?? '';
					this.registerPath = registerPath;
					this.loginPath = loginPath;
				} else {
					this.noPasskeysFlowSetup(settings);
				}
				console.log('Successfully init Crypto Module');
			});
	}

	private encrypt(data: string): string {
		return this.virgilCrypto.signThenEncrypt(data, this.encryptKeys.privateKey, [this.encryptKeys.publicKey, this.frontendPublicKey])
			.toString(this.encryptEncoding);
	}

	private decrypt(data: string): string {
		return this.virgilCrypto.decryptThenVerify(data, this.encryptKeys.privateKey, [this.encryptKeys.publicKey, this.frontendPublicKey])
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

	private loginFlow(key: string, res: Response): void {
		if (!key) {
			res.status(401);
			res.send({msg: 'Error! Need key inside!'});
			return;
		}
		this.setKey(key);
		res.send({
			key: this.virgilCrypto.exportPublicKey(this.encryptKeys.publicKey)
				.toString(this.encryptEncoding)
		});
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

	private noPasskeysFlow(req: Request, res: Response, next: CallableFunction) {
		if (req.url === this.loginPath && req.method === 'POST') {
			this.loginFlow(req.body.key, res);
			return next();
		}
		if (req.method === 'POST' || req.method === 'PUT') {
			this.postFlow(req, res);
			return next();
		}
		this.defaultFlow(res);
		return next();
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

	private async passkeysFlow(req: Request, res: Response, next: CallableFunction) {
		if (req.url === this.registerPath + '/start' && req.method === 'POST') {
			const username = req.body.username;
			const challenge = this.getNewChallenge();
			this.challenges.set(username, this.convertChallenge(challenge));
			const pubKey = {
				challenge: challenge,
				rp: {id: this.prId, name: 'webauthn-app'},
				user: {id: username, name: username, displayName: username},
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
		if (req.url === this.registerPath + '/finish' && req.method === 'POST') {
			const username = req.body.username;
			let verification;
			try {
				verification = await verifyRegistrationResponse({
					response: req.body.data,
					expectedChallenge: this.challenges.get(username)!,
					expectedOrigin: this.origin
				});
			} catch (error) {
				console.error(error);
				res.status(400);
				return next();
			}
			const {verified, registrationInfo} = verification;
			if (verified) {
				this.users.set(username, getRegistrationInfo(registrationInfo));
				res.status(200);
				return next();
			}
			res.status(500);
			return next();
		}
		if (req.url === this.loginPath + '/start' && req.method === 'POST') {
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
					allowCredentials: [{
						type: 'public-key',
						// eslint-disable-next-line @typescript-eslint/ban-ts-comment
						// @ts-ignore
						id: this.users.get(username).credentialID,
						transports: ['external'],
					}],
					userVerification: 'discouraged',
				}
			});
			res.status(200);
			return next();
		}
		if (req.url === this.loginPath + '/finish' && req.method === 'POST') {
			const username = req.body.username;
			if (!this.users.get(username)) {
				return res.status(404)
					.send(false);
			}
			let verification;
			try {
				const user = this.users.get(username);
				verification = await verifyAuthenticationResponse({
					expectedChallenge: this.challenges.get(username)!,
					response: req.body.data,
					authenticator: getSavedAuthenticatorData(user),
					expectedRPID: this.prId,
					expectedOrigin: origin
				});
			} catch (error) {
				console.error(error);
				res.status(400);
				return next();
			}
			const {verified} = verification;
			console.log(verified);
			res.status(200);
			return next();
		}
	}

	public zeroTrustMiddleware = async (req: Request, res: Response, next: CallableFunction) => {
		if (this.passkeysActive) {
			return this.passkeysFlow(req, res, next);
		}
		return this.noPasskeysFlow(req, res, next);
	};

}


export {
	ZtMiddleware
};
