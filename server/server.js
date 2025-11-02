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

// ✅ SERVIR ARQUIVOS ESTÁTICOS DO REACT (PRODUÇÃO)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  console.log('📁 Servindo arquivos estáticos do React...');
}

// Configuração do PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Testar conexão com o banco
const testConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('✅ Conectado ao PostgreSQL do Railway com sucesso!');
    client.release();
    return true;
  } catch (error) {
    console.error('❌ Erro ao conectar com o banco:', error.message);
    return false;
  }
};

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Middleware de autenticação
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
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// ==================== ROTAS DE AUTENTICAÇÃO ====================

// Registrar usuário
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Validações
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Nome é obrigatório' });
    }
    if (!email || !email.trim()) {
      return res.status(400).json({ error: 'Email é obrigatório' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
    }

    // Verificar se usuário já existe
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    // Hash da senha
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Criar usuário
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name.trim(), email.trim(), passwordHash]
    );

    // Gerar token JWT
    const token = jwt.sign({ userId: result.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      user: result.rows[0],
      token
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validações
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    // Buscar usuário
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.trim()]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Email ou senha incorretos' });
    }

    const user = result.rows[0];

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Email ou senha incorretos' });
    }

    // Gerar token JWT
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      token
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== ROTAS DE TAREFAS ====================

// Buscar todas as tarefas do usuário
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, category, time, date, deadline, completed, is_recurring, recurring_id, created_at
       FROM tasks 
       WHERE user_id = $1 
       ORDER BY date, time`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar tarefas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Criar nova tarefa
app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { title, category, time, date, deadline, completed = false, is_recurring = false, recurring_id = null } = req.body;

  try {
    // ✅ VALIDAÇÕES ROBUSTAS
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'O título da tarefa é obrigatório' });
    }

    if (!category) {
      return res.status(400).json({ error: 'A categoria é obrigatória' });
    }

    if (!date) {
      return res.status(400).json({ error: 'A data é obrigatória' });
    }

    // Validar formato da data
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(date)) {
      return res.status(400).json({ error: 'Formato de data inválido. Use YYYY-MM-DD' });
    }

    // Converter para Date para validação extra
    const taskDate = new Date(date);
    if (isNaN(taskDate.getTime())) {
      return res.status(400).json({ error: 'Data inválida' });
    }

    // Validar time se fornecido
    if (time && time !== '') {
      const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
      if (!timeRegex.test(time)) {
        return res.status(400).json({ error: 'Formato de horário inválido. Use HH:MM' });
      }
    }

    const result = await pool.query(
      `INSERT INTO tasks (user_id, title, category, time, date, deadline, completed, is_recurring, recurring_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        req.user.id, 
        title.trim(), 
        category, 
        time || null, 
        date, 
        deadline || null, 
        completed, 
        is_recurring, 
        recurring_id
      ]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar tarefa:', error);
    
    // Erro específico de data
    if (error.code === '22007') {
      return res.status(400).json({ error: 'Formato de data inválido' });
    }
    
    // Erro de chave estrangeira
    if (error.code === '23503') {
      return res.status(400).json({ error: 'Usuário não encontrado' });
    }
    
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Atualizar tarefa
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, category, time, date, deadline, completed } = req.body;

  try {
    // Verificar se a tarefa pertence ao usuário
    const taskCheck = await pool.query('SELECT id FROM tasks WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    
    if (taskCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Tarefa não encontrada para este usuário' });
    }

    // Validações
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'O título da tarefa é obrigatório' });
    }

    if (!category) {
      return res.status(400).json({ error: 'A categoria é obrigatória' });
    }

    if (!date) {
      return res.status(400).json({ error: 'A data é obrigatória' });
    }

    // Validar formato da data
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(date)) {
      return res.status(400).json({ error: 'Formato de data inválido. Use YYYY-MM-DD' });
    }

    const result = await pool.query(
      `UPDATE tasks 
       SET title = $1, category = $2, time = $3, date = $4, deadline = $5, completed = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND user_id = $8
       RETURNING *`,
      [title.trim(), category, time || null, date, deadline || null, completed, id, req.user.id]
    );
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('❌ Erro ao atualizar tarefa:', error);
    
    if (error.code === '22007') {
      return res.status(400).json({ error: 'Formato de data inválido' });
    }
    
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Deletar tarefa
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Verificar se a tarefa pertence ao usuário
    const taskCheck = await pool.query('SELECT id FROM tasks WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    if (taskCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Tarefa não encontrada' });
    }

    await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.json({ message: 'Tarefa deletada com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar tarefa:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== ROTAS DE TAREFAS RECORRENTES ====================

// Buscar tarefas recorrentes
app.get('/api/recurring-tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, category, time, repeat_type, days_of_week, day_of_month, created_at
       FROM recurring_tasks 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar tarefas recorrentes:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Criar tarefa recorrente
app.post('/api/recurring-tasks', authenticateToken, async (req, res) => {
  const { title, category, time, repeat_type, days_of_week, day_of_month } = req.body;

  try {
    // Validações
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'O título da tarefa é obrigatório' });
    }
    if (!category) {
      return res.status(400).json({ error: 'A categoria é obrigatória' });
    }
    if (!time) {
      return res.status(400).json({ error: 'O horário é obrigatório para tarefas recorrentes' });
    }
    if (!repeat_type) {
      return res.status(400).json({ error: 'O tipo de repetição é obrigatório' });
    }

    const result = await pool.query(
      `INSERT INTO recurring_tasks (user_id, title, category, time, repeat_type, days_of_week, day_of_month)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [req.user.id, title.trim(), category, time, repeat_type, days_of_week, day_of_month]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar tarefa recorrente:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Deletar tarefa recorrente
app.delete('/api/recurring-tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Verificar se a tarefa pertence ao usuário
    const taskCheck = await pool.query('SELECT id FROM recurring_tasks WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    if (taskCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Tarefa recorrente não encontrada' });
    }

    await pool.query('DELETE FROM recurring_tasks WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    
    // Também deletar tarefas geradas por esta recorrente
    await pool.query('DELETE FROM tasks WHERE recurring_id = $1 AND user_id = $2', [id, req.user.id]);
    
    res.json({ message: 'Tarefa recorrente e suas tarefas geradas deletadas com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar tarefa recorrente:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== INICIALIZAÇÃO DO BANCO ====================

const initDatabase = async () => {
  try {
    console.log('🔄 Inicializando banco de dados...');
    
    // Testar conexão primeiro
    const isConnected = await testConnection();
    if (!isConnected) {
      throw new Error('Não foi possível conectar ao banco de dados');
    }

    // Executar schema SQL
    const schema = `
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        is_recurring BOOLEAN DEFAULT FALSE,
        recurring_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS recurring_tasks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(50) NOT NULL,
        time TIME NOT NULL,
        repeat_type VARCHAR(20) NOT NULL,
        days_of_week INTEGER[],
        day_of_month INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
      CREATE INDEX IF NOT EXISTS idx_tasks_date ON tasks(date);
      CREATE INDEX IF NOT EXISTS idx_recurring_tasks_user_id ON recurring_tasks(user_id);
    `;

    await pool.query(schema);
    console.log('✅ Banco de dados inicializado com sucesso');
  } catch (error) {
    console.error('❌ Erro ao inicializar banco de dados:', error.message);
  }
};

// Rota de health check
app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW() as time');
    res.json({ 
      status: 'OK', 
      message: 'Study Planner API está funcionando!',
      database: 'Conectado',
      timestamp: new Date().toISOString(),
      dbTime: dbResult.rows[0].time
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      message: 'Problema na conexão com o banco',
      error: error.message 
    });
  }
});

// Rota raiz
app.get('/', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
  } else {
    res.json({ 
      message: 'Study Planner API - Modo Local', 
      version: '1.0.0',
      docs: '/api/health' 
    });
  }
});

// ✅ ROTA CATCH-ALL PARA REACT ROUTER (APENAS EM PRODUÇÃO)
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
  });
}

// Iniciar servidor
app.listen(port, async () => {
  console.log(`🚀 Servidor iniciado na porta ${port}`);
  console.log(`🌐 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Conectando ao banco do Railway...`);
  await initDatabase();
  
  if (process.env.NODE_ENV === 'production') {
    console.log(`✅ App completo rodando: https://seu-projeto.up.railway.app`);
  } else {
    console.log(`✅ Backend rodando: http://localhost:${port}`);
    console.log(`✅ Frontend rodando: http://localhost:3000`);
  }
  console.log(`🔍 Health check: /api/health`);
});