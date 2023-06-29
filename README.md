# Introduction
<hr>

### Virgil ZT Middleware

It's middleware for nodejs backend servers! Allow to simply implement information encoding. Using as core virgil-crypto lib!

# Using guide
- Install [virgil-crypto](https://www.npmjs.com/package/virgil-crypto) version 5.0.2 or newest 
- Install [@virgilsecurity/data-utils](https://www.npmjs.com/package/@virgilsecurity/data-utils) version 2.0.0 or newest

After this initialize class instance
```javascript
import { ZtMiddleware } from 'build';

const virgil = new ZtMiddleware(KeyPairType.ED25519, '/login');
```

```javascript
KeyPairType.ED25519
```
Argument it's key type, you can check other values on KeyPairType enum

```javascript
/login
``` 
It's login url, that will accept your frontend key

You can pass more than this two parameters:

- Storage interface function ```storageControl```
- Encoding default value is ```base64```

# What is storage

Let's see a full elements that ypu can pass into constructor

```javascript
const TemplateStorage: Map<string, any> = new Map<string, any>();

const storageSave = (key: unknown, isClient: boolean) => {
	TemplateStorage.set(isClient ? 'client' : 'server', key);
};

const storageLoad = (isClient: boolean) => {
	return isClient ? TemplateStorage.get('client') : TemplateStorage.get('server');
};

function storage(isSave: boolean, isClient: boolean, key?: unknown) {
	if (isSave) {
		storageSave(key, isClient);
		return;
	}
	return storageLoad(isClient);
}

const virgil = new ZtMiddleware(KeyPairType.ED25519, '/login', storage, 'base64');
```

The storage function is interface for working with files or another save instrument. Upper we realize simple storage, to collect server and clients keys. We are saving this in TypeScript Map, then convert in .json file after server broke. When server is up again we can load this keys and using them. You can create your own storage logic, all that you need is create function like: 

```javascript
storage(isSave: boolean, isClient: boolean, key?: unknown)
```

Then pass it inside constructor, we will save keys and get it, if needed.

# Pass middleware into nodejs

```javascript
app.use(virgil.zeroTrustMiddleware);
```

After this, on frontend you need to pass keys on login url. Save key on frontend and that's all. Encryption is ready for use!

For more information you can check [example/backend](https://github.com/VirgilSecurity/virgil-zt-js/tree/main/example/backend) and [example/frontend](https://github.com/VirgilSecurity/virgil-zt-js/tree/main/example/frontend) to see how it's working.
