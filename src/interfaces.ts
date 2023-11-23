import { VirgilPrivateKey } from 'virgil-crypto/dist/types/VirgilPrivateKey';
import { VirgilPublicKey } from 'virgil-crypto/dist/types/VirgilPublicKey';
import { KeyPairType } from 'virgil-crypto';


export interface CryptoKeys {
	privateKey: VirgilPrivateKey;
	publicKey: VirgilPublicKey;
}

export interface Settings {
	passkeyFlow: boolean,
	loginPath: string,
	registerPath: string,
	keyType: KeyPairType,
	replayingId?: string,
	expectedOrigin?: string,
	storageControl?: CallableFunction,
	encoding?: BufferEncoding
}
