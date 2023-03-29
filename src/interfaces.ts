import {VirgilPrivateKey} from 'virgil-crypto/dist/types/VirgilPrivateKey';
import {VirgilPublicKey} from 'virgil-crypto/dist/types/VirgilPublicKey';

export interface CryptoKeys {
	privateKey: VirgilPrivateKey;
	publicKey: VirgilPublicKey;
}
