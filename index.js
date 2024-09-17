const express = require('express');
const cors = require('cors'); // Importa o middleware CORS
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Configura o middleware CORS para permitir apenas o domínio específico
app.use(cors({
  origin: 'https://start-ai-lyart.vercel.app'
}));

app.use(express.json());

//ROTAS AUTH

// Criar-Conta
app.post('/criar-conta', async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
  });

  if (error) {
    return res.status(400).json({ error: error.message });
  }

  res.status(201).json({ user: data.user });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    return res.status(400).json({ error: error.message });
  }

  res.status(200).json({ session: data.session });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
