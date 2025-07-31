const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'https://gleaming-meerkat-0fdcfc.netlify.app/', // Usa a variável de ambiente FRONTEND_URL
    credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: 'Muitas tentativas. Tente novamente em 15 minutos.'
});
app.use('/api/', limiter);

// Simulação de banco de dados (em produção, use MongoDB, PostgreSQL, etc.)
let users = [];

// Middleware de validação de email
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Middleware de validação de senha
const isValidPassword = (password) => {
    return password && password.length >= 6;
};

// Rota de teste
app.get('/', (req, res) => {
    res.json({
        message: 'API de Registro funcionando!',
        version: '1.0.0',
        endpoints: {
            register: 'POST /api/register',
            login: 'POST /api/login',
            users: 'GET /api/users (dev only)'
        }
    });
});

// Rota de registro
app.post('/api/register', async (req, res) => {
    try {
        const { email, senha } = req.body;

        // Validações
        if (!email || !senha) {
            return res.status(400).json({
                success: false,
                message: 'Email e senha são obrigatórios!'
            });
        }

        if (!isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Por favor, forneça um email válido!'
            });
        }

        if (!isValidPassword(senha)) {
            return res.status(400).json({
                success: false,
                message: 'A senha deve ter pelo menos 6 caracteres!'
            });
        }

        // Verificar se usuário já existe
        const userExists = users.find(user => user.email === email);
        if (userExists) {
            return res.status(409).json({
                success: false,
                message: 'Usuário já existe com este email!'
            });
        }

        // Hash da senha
        const saltRounds = 12;
        const senhaHash = await bcrypt.hash(senha, saltRounds);

        // Criar novo usuário
        const newUser = {
            id: Date.now().toString(),
            email: email.toLowerCase(),
            senha: senhaHash,
            criadoEm: new Date().toISOString()
        };

        users.push(newUser);

        // Gerar JWT token
        const token = jwt.sign(
            { userId: newUser.id, email: newUser.email },
            process.env.JWT_SECRET || 'sua-chave-secreta-muito-segura',
            { expiresIn: '24h' }
        );

        console.log(`Novo usuário registrado: ${email}`);

        res.status(201).json({
            success: true,
            message: 'Conta criada com sucesso!',
            data: {
                id: newUser.id,
                email: newUser.email,
                criadoEm: newUser.criadoEm
            },
            token
        });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Rota de login
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(400).json({
                success: false,
                message: 'Email e senha são obrigatórios!'
            });
        }

        // Buscar usuário
        const user = users.find(u => u.email === email.toLowerCase());
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas!'
            });
        }

        // Verificar senha
        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) {
            return res.status(401).json({
                success: false,
                message: 'Credenciais inválidas!'
            });
        }

        // Gerar JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET || 'sua-chave-secreta-muito-segura',
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Login realizado com sucesso!',
            data: {
                id: user.id,
                email: user.email,
                criadoEm: user.criadoEm
            },
            token
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

// Middleware de autenticação JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token de acesso requerido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'sua-chave-secreta-muito-segura', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Rota protegida - perfil do usuário
app.get('/api/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            criadoEm: user.criadoEm
        }
    });
});

// Rota para listar usuários (apenas para desenvolvimento)
app.get('/api/users', (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({ message: 'Endpoint não disponível em produção' });
    }

    const usersData = users.map(user => ({
        id: user.id,
        email: user.email,
        criadoEm: user.criadoEm
    }));

    res.json({
        success: true,
        count: usersData.length,
        data: usersData
    });
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Algo deu errado!'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Rota não encontrada'
    });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || 'development'}`);
});