Aplicar **cibersegurança** no código envolve seguir boas práticas de desenvolvimento seguro. Aqui estão algumas diretrizes para proteger suas aplicações:

---

## **1. Proteção de Senhas e Autenticação**
✅ **Use hash seguro para senhas**  
Nunca armazene senhas em texto puro. Utilize um algoritmo forte como **bcrypt**:
```js
const bcrypt = require('bcrypt');
const saltRounds = 10;
const hashedPassword = await bcrypt.hash('senha123', saltRounds);
```
✅ **Implemente autenticação de dois fatores (2FA)**  
Pode ser feito com **Google Authenticator** ou **SMS** usando bibliotecas como `speakeasy`:
```js
const speakeasy = require('speakeasy');
const secret = speakeasy.generateSecret();
console.log(secret.otpauth_url); // Use em um app de autenticação
```
✅ **Evite expor tokens e senhas no código**  
Use variáveis de ambiente (`.env`) ao invés de deixá-los no código:
```bash
DATABASE_URL=mongodb://usuario:senha@servidor
```
E no código:
```js
require('dotenv').config();
const dbUrl = process.env.DATABASE_URL;
```

---

## **2. Prevenção contra SQL Injection e NoSQL Injection**
✅ **Use queries preparadas no SQL**:
```js
const db = require('mysql2/promise');
const connection = await db.createConnection({ /* Configuração */ });

const [rows] = await connection.execute('SELECT * FROM usuarios WHERE email = ?', [email]);
```
✅ **Evite consultas diretas no MongoDB** (NoSQL Injection)  
Nunca faça:
```js
const user = await db.users.findOne({ email: req.body.email }); // Perigo 🚨
```
Use **sanitização e validação**:
```js
const user = await db.users.findOne({ email: sanitize(req.body.email) });
```

---

## **3. Proteção contra XSS (Cross-Site Scripting)**
✅ **Escape dados antes de renderizar HTML**  
Se estiver usando **React**, use `dangerouslySetInnerHTML` com cautela. Em **Express.js**, use `helmet`:
```js
const helmet = require('helmet');
app.use(helmet());
```
✅ **Sanitize inputs do usuário**  
```js
const sanitizeHtml = require('sanitize-html');
const cleanInput = sanitizeHtml(userInput, { allowedTags: [], allowedAttributes: {} });
```

---

## **4. Proteção contra CSRF (Cross-Site Request Forgery)**
✅ **Use tokens CSRF em requisições sensíveis**  
Se estiver usando Express:
```js
const csurf = require('csurf');
app.use(csurf());
```

---

## **5. Segurança em APIs**
✅ **Sempre valide e limite os dados recebidos**  
```js
const Joi = require('joi');
const schema = Joi.object({
  email: Joi.string().email().required(),
  senha: Joi.string().min(8).required()
});

const { error } = schema.validate(req.body);
if (error) return res.status(400).send(error.details[0].message);
```
✅ **Proteja endpoints sensíveis com autenticação**  
Use **JWT com expiração curta**:
```js
const jwt = require('jsonwebtoken');
const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
```
✅ **Rate limiting para evitar ataques de força bruta**  
```js
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // Limite de requisições
});
app.use(limiter);
```

---

## **6. Logs e Monitoramento**
✅ **Registre atividades suspeitas**  
Use **Winston** para logar eventos de segurança:
```js
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  transports: [ new winston.transports.File({ filename: 'logs/app.log' }) ]
});
logger.info('Usuário fez login');
```
✅ **Proteja logs contra vazamentos**  
Não registre dados sensíveis como senhas ou tokens.

---

## **7. Atualizações e Patching**
✅ **Mantenha pacotes atualizados**  
Sempre use `npm audit` para verificar vulnerabilidades:
```bash
npm audit fix
```
Ou instale pacotes apenas de fontes confiáveis.

---

### **Resumo das principais práticas**
| Ameaça | Solução |
|--------|---------|
| Senhas fracas | Hash com **bcrypt** e 2FA |
| SQL Injection | **Queries preparadas** |
| NoSQL Injection | **Sanitização de inputs** |
| XSS | **Escape de dados e sanitização** |
| CSRF | **Tokens CSRF** |
| Força bruta | **Rate limiting e logs** |
| Vazamento de credenciais | **Uso de variáveis de ambiente** |
| Ataques em APIs | **JWT, validação e CORS** |

Quer um exemplo mais completo de código seguro para uma API? 🚀
