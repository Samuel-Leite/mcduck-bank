const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
  ssl: true, // Certifique-se de configurar SSL corretamente para produção
});

const app = express();
const port = process.env.PORT || 3000;

// Middleware para fazer o parsing do corpo das requisições
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Chave secreta para assinar os tokens JWT
const SECRET_KEY = process.env.SECRET_KEY || "chave-secreta-default";

// Servir arquivos estáticos (por exemplo, páginas HTML)
app.use(express.static(path.join(__dirname, "../web")));

// Função para obter cliente do pool e liberá-lo ao final
const getClient = async () => {
  const client = await pool.connect();
  return {
    client,
    release: () => client.release(),
  };
};

// Middleware para verificação de autenticação via token JWT
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "Token não fornecido" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Token inválido" });
    req.userId = decoded.id;
    next();
  });
}

// Middleware para gerar um novo token JWT
function generateToken(userId) {
  return jwt.sign({ id: userId }, SECRET_KEY, {
    expiresIn: "1h", // Token expira em 1 hora
  });
}

// Rota para método GET (exemplo: lista de usuários)
app.get("/auth/users", async (req, res) => {
  try {
    const { client, release } = await getClient();
    const result = await client.query("SELECT * FROM users");
    release();
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Erro ao buscar usuários", err);
    res.status(500).json({ error: "Erro ao buscar usuários" });
  }
});

// Rota para método POST (exemplo: cadastro de usuário)
app.post("/auth/signup", async (req, res) => {
  const { username, cpf, email, address, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash da senha
    const client = await pool.connect();
    const result = await client.query(
      "INSERT INTO users (username, cpf, email, address, password) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [username, cpf, email, address, hashedPassword]
    );
    client.release();

    res
      .status(201)
      .json({
        message: "Usuário cadastrado com sucesso!",
        user: result.rows[0],
      });
  } catch (err) {
    console.error("Erro ao cadastrar usuário:", err);
    res.status(500).json({ error: "Erro ao cadastrar usuário" });
  }
});

// Rota para login com geração de token JWT e refresh token
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const user = result.rows[0];
    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const token = generateToken(user.id);
    const refreshToken = jwt.sign({ id: user.id }, SECRET_KEY + "_refresh", {
      expiresIn: "7d",
    }); // Refresh token válido por 7 dias

    res.status(200).json({ token, refreshToken });
  } catch (err) {
    console.error("Erro ao realizar login:", err);
    res.status(500).json({ error: "Erro interno ao realizar login" });
  }
});

// Rota para refresh do token
app.post("/auth/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;

  try {
    jwt.verify(refreshToken, SECRET_KEY + "_refresh", (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: "Refresh token inválido" });
      }

      const token = generateToken(decoded.id);
      res.status(200).json({ token });
    });
  } catch (err) {
    console.error("Erro ao atualizar token:", err);
    res.status(500).json({ error: "Erro interno ao atualizar token" });
  }
});

// Rota protegida para acessar a home após o login
app.get("/auth/home", verifyToken, (req, res) => {
  // Rota protegida, apenas acessível com token válido
  res.status(200).json({ message: "Bem-vindo à home do McDuck Bank" });
});

// Rota para limpar a tabela de usuários e reiniciar a sequência
app.delete("/auth/clear-users", async (req, res) => {
  try {
    const { client, release } = await getClient();

    // Deletar todos os registros da tabela 'users'
    const queryDelete = "DELETE FROM users";
    await client.query(queryDelete);

    // Reiniciar a sequência associada ao ID da tabela 'users'
    const queryRestartSeq = "ALTER SEQUENCE users_id_seq RESTART WITH 1"; // ajuste o nome da sequência conforme necessário
    await client.query(queryRestartSeq);

    release();

    res.status(200).json({
      message:
        "Todos os registros da tabela 'users' foram removidos e a sequência foi reiniciada.",
    });
  } catch (err) {
    console.error("Erro ao limpar tabela 'users' e reiniciar sequência:", err);
    res
      .status(500)
      .json({ error: "Erro ao limpar tabela 'users' e reiniciar sequência" });
  }
});

// Rota para servir a página de login/cadastro
app.get("/auth/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../web", "pages", "login.html"));
});

// Rota para servir o arquivo HTML principal
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../web", "index.html"));
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
