const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'postgres-production-3716.up.railway.app'],
  credentials: true
}));
app.use(express.json());

// Configuração do PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'startup_com_o_vini_2026';

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
      [name, email, passwordHash]
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
    // Buscar usuário
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
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
    const result = await pool.query(
      `INSERT INTO tasks (user_id, title, category, time, date, deadline, completed, is_recurring, recurring_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [req.user.id, title, category, time, date, deadline, completed, is_recurring, recurring_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar tarefa:', error);
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
      return res.status(404).json({ error: 'Tarefa não encontrada' });
    }

    const result = await pool.query(
      `UPDATE tasks 
       SET title = $1, category = $2, time = $3, date = $4, deadline = $5, completed = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND user_id = $8
       RETURNING *`,
      [title, category, time, date, deadline, completed, id, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao atualizar tarefa:', error);
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
    const result = await pool.query(
      `INSERT INTO recurring_tasks (user_id, title, category, time, repeat_type, days_of_week, day_of_month)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [req.user.id, title, category, time, repeat_type, days_of_week, day_of_month]
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
    console.error('❌ Erro ao inicializar banco de dados:', error);
  }
};

// Rota de health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Study Planner API está funcionando!' });
});

app.listen(port, async () => {
  await initDatabase();
  console.log(`🚀 Servidor rodando na porta ${port}`);
});