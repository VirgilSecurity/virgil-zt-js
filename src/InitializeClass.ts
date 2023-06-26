import {
	initCrypto,
	KeyPairType,
	VirgilCrypto
} from 'virgil-crypto';
import { CryptoKeys } from './interfaces';
import {
	Request,
	Response
} from 'express';
import { NodeBuffer } from '@virgilsecurity/data-utils';
import { VirgilPublicKey } from 'virgil-crypto/dist/types/VirgilPublicKey';


class ZtMiddleware {

	private encryptKeys: CryptoKeys;
	private virgilCrypto: VirgilCrypto;
	private frontendPublicKey: VirgilPublicKey;
	private loginPath: string;
	private encryptEncoding: BufferEncoding;
	private storageSave: Function;
	private storageLoad: Function;

	/*
		Initialize crypto module to upload wasm and other files
	 */
	private static initializeCryptoModule = async () => {
		await initCrypto();
	};

	constructor(keyType: KeyPairType, loginPath: string, encoding: BufferEncoding = 'base64', storageSaveInterface: Function, storageLoadInterface: Function) {
		ZtMiddleware.initializeCryptoModule()
			.then(() => {
				this.virgilCrypto = new VirgilCrypto({defaultKeyPairType: keyType});
				this.encryptKeys = this.virgilCrypto.generateKeys();
				this.loginPath = loginPath;
				this.encryptEncoding = encoding;
				if (storageSaveInterface) {
					this.storageSave = storageSaveInterface;
					this.storageSave(this.encryptKeys, false);
				}
				if (storageLoadInterface) {
					this.storageLoad = storageLoadInterface;
					this.encryptKeys = this.storageLoad();
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
		if (this.storageLoad(true)) {
			this.frontendPublicKey = this.storageLoad(true);
			return;
		}
		this.frontendPublicKey = this.virgilCrypto.importPublicKey(NodeBuffer.from(key, 'base64'));
		if (this.storageSave) {
			this.storageSave(this.frontendPublicKey, true);
		}
	}

	private rewriteResponse(res: Response) {
		const oldJson = res.json;
		res.json = (body) => {
			res.locals.body = body;
			body = {data: this.encrypt(typeof (body.data) === 'string' ? body.data : JSON.stringify(body.data))};
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

	public zeroTrustMiddleware = async (req: Request, res: Response, next: Function) => {
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
	};

}


export {
	ZtMiddleware
};
