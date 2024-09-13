import * as dotenv from 'dotenv'
dotenv.config({ path: './.env' }) // process.env.JWT_SECRET
import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const jwtSecret = process.env.JWT_SECRET; // env

// true ? foo(true) : foo(false)
// foo(true | false) ?? true
// 10 ?? 5 => 10
// a ?? b 
// Если а определено тогда а ?? если а не определено тогда b

//Middleware custom
function authJWT(req, res, next) {
    // 1. Извлечь строку 'Bearer + токен' из headers
    const authHeader = req.headers.authorization;
    // 2. Проверяем заголовка и будет ли он 'Bearer'
    if (authHeader && authHeader.startsWith('Bearer ')) { // 7 - 
        const token = authHeader.substring(7, authHeader.length) // qwertyu.dfghj.zxcvbn 
        // Выполняем проверку
        jwt.verify(token, jwtSecret, (err, user) => {
            if (err) {
                return res.status(403).send('Неправильный или истекший токен')
            }
            req.user = user
            next();
        })
    } else {
        return res.status(401).send('Неавторизованный пользователь: нет токена')
    }
}

function authRole(role) {
    return (req, res, next) => {
        if (req.user.role === 'Admin') {
            next();
        } else if (req.user.role === 'simpleUser') {
            req.user.role = 'Admin'
            //
            next();
        } else {
            return res.status(403).send('Don\'t have access')
        }
    }
}

const app = express();
// Middleware
app.use(express.json()); // middleware для обработки Request
// app.use(authJWT) // Все запросы 

const users = [{
    id: '1',
    email: 'jack@sparrow.com',
    password: await bcrypt.hash('1234qwerty', 10)
}, {
    id: '007',
    email: 'bond@james.com',
    password: await bcrypt.hash('1234qwerty', 10),
    role: 'Admin'
}]

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // 1. Пользователь есть
        const user = users.find((u) => u.email === email) // {} | undefined
        if (!user) {
            return res.status(404).send('Пользователь не найден') // .json({message: 'Пользователь не найден'})
        }

        // 2. Проверка пароль          // nonDecodePass   decopePass
        const isMatch = await bcrypt.compare(password, user.password) // true | false

        if (!isMatch) {
            return res.status(401).send('Пароль не верный')
        }

        // 3. Отправляем jwt токен                    
        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role ?? 'simpleUser' }, // Payload
            jwtSecret, // Секретик
            { expiresIn: '1h' } // время жизни токена
        )

        // 4. Отправка токена
        res.json({ token })

    } catch (err) {
        res.status(500).send('Ошибка сервера')
    }
})

app.get('/protected', authJWT, (req, res) => {
    console.log(req.user);
    res.json({ message: 'Защищено', user: req.user })
});

app.get('/me', authJWT, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        message: 'Привет вот твои защищенные данные'
    })
})

app.get('/admin', authJWT, authRole('Admin'), () => {
    res.send('Welcome admin');
})

// Middleware
// app.use(test) // middleware для обработки Response

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
})