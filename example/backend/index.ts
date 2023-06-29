import express, {
	Express,
	Request,
	Response
} from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
// @ts-ignore
import { ZtMiddleware } from 'build';
import * as fs from 'fs';
import { KeyPairType } from 'virgil-crypto';


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

const app: Express = express();

const virgil = new ZtMiddleware(KeyPairType.ED25519, '/login', storage, 'base64');

app.use(bodyParser.json());
app.use(cors());
app.use(virgil.zeroTrustMiddleware);

app.get('/', (req: Request, res: Response) => {
	res.send({data: 'Hello World!'});
});
app.post('/post', (req: Request, res: Response) => {
	res.send({data: req.body});
});
app.post('/new-post', (req: Request, res: Response) => {
	res.send({data: {name: 'Tester', password: 'pass'}});
});

const server = app.listen(3001, () => {
	console.log('Server is running');
});

[ 'exit', 'SIGINT', 'SIGUSR1', 'SIGUSR2', 'uncaughtException', 'SIGTERM' ].forEach((eventType) => {
	process.on(eventType, () => {
		console.log('write to file');
		const saveObject: {serverKeys: unknown[], clientKeys: unknown[]} = {serverKeys: [], clientKeys: []};
		TemplateStorage.forEach((value: unknown, key) => {
			if (key == 'server') {
				saveObject.serverKeys.push(value);
			} else {
				saveObject.clientKeys.push(value);
			}
		});
		fs.writeFile('storage.json', JSON.stringify(saveObject), (err) => {
			console.log(err);
			console.log('Saved to file!');
		});
	});
});


