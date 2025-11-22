const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://seu-projeto.up.railway.app', 'http://localhost:3000']
    : 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// SERVIR ARQUIVOS ESTÁTICOS DO REACT (PRODUÇÃO)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  console.log('📁 Servindo arquivos estáticos do React...');
}

// CONFIGURAÇÃO OTIMIZADA PARA RAILWAY
const poolConfig = {
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  // Configurações otimizadas para Railway
  max: 10,
  min: 2,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000, // Aumentado para 30 segundos
  query_timeout: 30000,
  statement_timeout: 30000,
  keepAlive: true
};

console.log('🔧 Configurando conexão com Railway PostgreSQL...');
console.log('📍 Host: shinkansen.proxy.rlwy.net:34963');

const pool = new Pool(poolConfig);

// Testar conexão com timeout maior
const testConnection = async () => {
  let client;
  try {
    console.log('🔌 Testando conexão com Railway PostgreSQL (timeout: 30s)...');
    
    // Usar Promise.race para timeout customizado
    const connectionPromise = pool.connect();
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout de conexão após 30 segundos')), 30000)
    );
    
    client = await Promise.race([connectionPromise, timeoutPromise]);
    
    const result = await client.query('SELECT NOW() as current_time');
    console.log('✅ Conectado ao Railway PostgreSQL com sucesso!');
    console.log('🕒 Hora do banco:', result.rows[0].current_time);
    return true;
  } catch (error) {
    console.error('❌ Erro na conexão:', error.message);
    
    // Dicas específicas baseadas no erro
    if (error.message.includes('timeout')) {
      console.log('💡 Dica: O Railway pode estar sob carga. Tente novamente em alguns segundos.');
    } else if (error.message.includes('SSL') || error.message.includes('TLS')) {
      console.log('💡 Dica: Verifique a configuração SSL no Railway.');
    }
    
    return false;
  } finally {
    if (client) client.release();
  }
};

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de autenticação (mantido igual)
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso necessário' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [decoded.userId]);
    
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    req.user = user.rows[0];
    next();
  } catch (error) {
    console.error('Erro na autenticação:', error.message);
    return res.status(403).json({ error: 'Token inválido ou expirado' });
  }
};

// ==================== ROTAS BÁSICAS (SEM AUTENTICAÇÃO PARA TESTE) ====================

// Health check sem autenticação
app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW() as time');
    res.json({ 
      status: 'OK', 
      message: 'Study Planner API está funcionando!',
      database: 'Conectado',
      timestamp: new Date().toISOString(),
      dbTime: dbResult.rows[0].time,
      environment: process.env.NODE_ENV
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'ERROR', 
      message: 'Problema na conexão com o banco',
      error: error.message,
      environment: process.env.NODE_ENV
    });
  }
});

// Rota de teste simples
app.get('/api/test', async (req, res) => {
  try {
    const result = await pool.query('SELECT 1+1 as result');
    res.json({ 
      message: 'Conexão com banco OK!',
      test: result.rows[0].result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Erro no teste de banco',
      message: error.message 
    });
  }
});

// ==================== ROTAS DE AUTENTICAÇÃO ====================

// Registrar usuário
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    if (!name || !name.trim()) return res.status(400).json({ error: 'Nome é obrigatório' });
    if (!email || !email.trim()) return res.status(400).json({ error: 'Email é obrigatório' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });

    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) return res.status(400).json({ error: 'Email já cadastrado' });

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name.trim(), email.trim(), passwordHash]
    );

    const token = jwt.sign({ userId: result.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({ user: result.rows[0], token });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.trim()]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Email ou senha incorretos' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Email ou senha incorretos' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: { id: user.id, name: user.name, email: user.email },
      token
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});


app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, category, time, date, deadline, completed, created_at
       FROM tasks WHERE user_id = $1 ORDER BY date, time`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar tarefas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});


app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { title, category, time, date, deadline, completed = false } = req.body;

  try {
    if (!title?.trim()) return res.status(400).json({ error: 'Título é obrigatório' });
    if (!category) return res.status(400).json({ error: 'Categoria é obrigatória' });
    if (!date) return res.status(400).json({ error: 'Data é obrigatória' });

    const result = await pool.query(
      `INSERT INTO tasks (user_id, title, category, time, date, deadline, completed)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.user.id, title.trim(), category, time || null, date, deadline || null, completed]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar tarefa:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== INICIALIZAÇÃO DO BANCO ====================

const initDatabase = async () => {
  let retryCount = 0;
  const maxRetries = 5; // Aumentado para 5 tentativas
  
  const attemptConnection = async () => {
    try {
      console.log(`🔄 Tentativa ${retryCount + 1} de ${maxRetries}...`);
      
      const isConnected = await testConnection();
      if (!isConnected) throw new Error('Não foi possível conectar ao banco');

      // Schema simplificado para teste
      const schema = `
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tasks (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          title VARCHAR(255) NOT NULL,
          category VARCHAR(50) NOT NULL,
          time TIME,
          date DATE NOT NULL,
          deadline DATE,
          completed BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `;

      await pool.query(schema);
      console.log('✅ Banco de dados inicializado com sucesso');
      return true;
    } catch (error) {
      console.log(`❌ Tentativa ${retryCount + 1} falhou:`, error.message);
      retryCount++;
      
      if (retryCount < maxRetries) {
        const delay = Math.min(5000 * retryCount, 30000); // Backoff exponencial
        console.log(`⏳ Aguardando ${delay/1000} segundos...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        return attemptConnection();
      } else {
        console.log('💥 Todas as tentativas falharam. Servidor iniciará sem banco.');
        return false;
      }
    }
  };

  return await attemptConnection();
};

// Rota raiz
app.get('/', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
  } else {
    res.json({ 
      message: 'Study Planner API', 
      status: 'Online',
      health: '/api/health',
      test: '/api/test'
    });
  }
});

// ROTA CATCH-ALL PARA REACT ROUTER
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
  });
}

// Iniciar servidor
const startServer = async () => {
  console.log(`🚀 Iniciando servidor na porta ${port}`);
  console.log(`🌐 Ambiente: ${process.env.NODE_ENV}`);
  
  const dbInitialized = await initDatabase();
  
  app.listen(port, () => {
    console.log(`✅ Servidor rodando na porta ${port}`);
    console.log(`🔍 Health check: http://localhost:${port}/api/health`);
    console.log(`🧪 Teste: http://localhost:${port}/api/test`);
    console.log(`🗄️  Banco: ${dbInitialized ? '✅ Conectado' : '❌ Desconectado'}`);
  });
};

startServer().catch(console.error);