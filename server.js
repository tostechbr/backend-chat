const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const users = []; // Armazenamento local de usuários

// Log inicial para garantir que o servidor está iniciando
console.log("Iniciando servidor...");

// Rota de registro
app.post('/api/users/register', async (req, res) => {
    console.log("Rota de registro chamada");
    const { email, password } = req.body;
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'Usuário já existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ email, password: hashedPassword });

    res.status(201).json({ message: 'Usuário criado com sucesso' });
});

// Rota de login
app.post('/api/users/login', async (req, res) => {
    console.log("Rota de login chamada");
    const { email, password } = req.body;
    const user = users.find(user => user.email === email);
    if (!user) {
        return res.status(400).json({ message: 'Credenciais inválidas' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ email: user.email }, 'secret', { expiresIn: '1h' });
    res.status(200).json({ token });
});

// Middleware de autenticação
const auth = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ message: 'Acesso negado' });
    }

    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Token inválido' });
    }
};

// Rota protegida de exemplo
app.get('/api/protected', auth, (req, res) => {
    console.log("Rota protegida chamada");
    res.status(200).json({ message: 'Você acessou uma rota protegida!', user: req.user });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
