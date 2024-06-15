const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
  ssl: { rejectUnauthorized: false },
});

const app = express();
const port = process.env.PORT || 3000;

// Middleware para fazer o parsing do corpo das requisições
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
    const { client, release } = await getClient();
    const query =
      "INSERT INTO users (username, cpf, email, address, password) VALUES ($1, $2, $3, $4, $5)";
    const values = [username, cpf, email, address, password];
    await client.query(query, values);
    release();
    res.status(201).json({ message: "Usuário cadastrado com sucesso!" });
  } catch (err) {
    console.error("Erro ao cadastrar usuário", err);
    res.status(500).json({ error: "Erro ao cadastrar usuário" });
  }
});

// Rota para método DELETE (exemplo: limpar tabela de usuários)
// Rota para método DELETE (exemplo: limpar tabela de usuários)
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
      message: "Todos os registros da tabela 'users' foram removidos e a sequência foi reiniciada.",
    });
  } catch (err) {
    console.error("Erro ao limpar tabela 'users' e reiniciar sequência:", err);
    res.status(500).json({ error: "Erro ao limpar tabela 'users' e reiniciar sequência" });
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
