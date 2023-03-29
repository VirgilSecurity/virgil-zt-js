import express, {Express, Request, Response} from 'express';
import * as http from 'http';
import {KeyPairType} from 'virgil-crypto';
import bodyParser from 'body-parser';
import cors from "cors"

const app: Express = express()
const server = http.createServer(app);

const virgil = new ZtMiddleware(KeyPairType.ED25519, "/login");

app.use(bodyParser.json())
app.use(cors())
app.use(virgil.zeroTrustMiddleware);

app.get('/', (req: Request, res: Response) => {
	res.send({data: 'Hello World!'});
})
app.post('/post', (req: Request, res: Response) => {
	res.send({data: req.body})
})
app.post('/new-post', (req: Request, res: Response) => {
	res.send({data: {name: 'Tester', password: 'pass'}})
})

server.listen(3001, ()=> {
	console.log('Server is running');
})



