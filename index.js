const express = require('express');
const cors = require('cors'); // Importa o middleware CORS
const { createClient } = require('@supabase/supabase-js');
const argon2 = require('argon2'); // Altera para argon2
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Configura o middleware CORS para permitir apenas o domínio específico
app.use(cors({
  origin: ['https://startai.vercel.app', 'https://startai-startai-ais-projects.vercel.app', 'http://localhost:4200']
}));

app.use(express.json());

// ROTAS AUTH

// Criar-Conta
app.post('/registrar', async (req, res) => {
  const { nome, email, senha, dataNascimento, controle } = req.body;

  // Valida se todos os campos foram preenchidos
  if (!nome || !email || !senha || !dataNascimento || !controle) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    // Verifica quantos usuários já existem com o mesmo e-mail
    const { data: existingUsers, error: countError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email);

    if (countError) {
      throw countError;
    }

    // Permite até dois usuários com o mesmo e-mail
    if (existingUsers.length >= 2) {
      return res.status(400).json({ error: 'Já existem dois usuários com este e-mail.' });
    }

    // Criptografa a senha
    const hashedPassword = await argon2.hash(senha); // Altera para argon2

    // Insere os dados na tabela Usuario
    const { data: userData, error: userError } = await supabase
      .from('Usuario')
      .insert([{ nome, email, senha: hashedPassword, dataNascimento }])
      .select()
      .single();

    if (userError) {
      throw userError;
    }

    // Seleciona o usuário recém-cadastrado
    const { data: newUser, error: selectError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('id', userData.id)
      .single();

    if (selectError) {
      throw selectError;
    }

    // Insere o controle na tabela User_controle
    const { error: controleError } = await supabase
      .from('User_controle')
      .insert([{ user_id: newUser.id, controle_id: controle }]);

    if (controleError) {
      await supabase
        .from('Usuario')
        .delete()
        .eq('id', newUser.id);

      return res.status(400).json({ error: 'Erro ao associar o controle. Usuário não registrado.' });
    }

    res.status(201).json({ message: 'Usuário cadastrado com sucesso!', user: newUser });
  } catch (error) {
    console.error('Erro ao cadastrar usuário:', error);
    res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  // Valida se todos os campos foram preenchidos
  if (!email || !senha) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    // Busca o usuário pelo email
    const { data: existingUser, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email)
      .single(); // Use .single() para garantir que você pega um único usuário

    if (userError || !existingUser) {
      return res.status(400).json({ error: 'Email não cadastrado.' });
    }

    // Compara a senha fornecida com a senha armazenada
    const passwordMatch = await argon2.verify(existingUser.senha, senha); // Altera para argon2
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // Busca o controle associado ao usuário
    const { data: userControle, error: controleError } = await supabase
      .from('User_controle')
      .select('controle_id')
      .eq('user_id', existingUser.id)
      .single();

    if (controleError) {
      console.error('Erro ao buscar controle do usuário:', controleError);
      return res.status(500).json({ error: 'Erro ao buscar controle do usuário.' });
    }

    // Remove a senha do objeto do usuário para que ela não seja retornada
    const userWithoutPassword = { ...existingUser };
    delete userWithoutPassword.senha;

    // Login bem-sucedido
    res.status(200).json({
      message: 'Login bem-sucedido!',
      user: userWithoutPassword,
      controleId: userControle.controle_id // Retorna o controle_id, se existir
    });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
});

// Rota para atualizar o nome do usuário (com confirmação de senha)
app.put('/perfil/nome', authenticate, (req, res) => {
  const usuario = getCurrentUser(req);
  const { nome, senha } = req.body;

  if (usuario) {
    // Verifica se a senha confere
    if (usuario.senha === senha) {
      usuario.nome = nome;
      res.json({ message: 'Nome atualizado com sucesso.', usuario });
    } else {
      res.status(403).json({ error: 'Senha incorreta.' });
    }
  } else {
    res.status(404).json({ error: 'Usuário não encontrado.' });
  }
});

// Rota para atualizar a senha do usuário (com verificação da data de nascimento)
app.put('/perfil/senha', authenticate, (req, res) => {
  const usuario = getCurrentUser(req);
  const { novaSenha, dataNascimento } = req.body;

  if (usuario) {
    // Verifica se a data de nascimento confere com o registro
    if (usuario.dataNascimento === dataNascimento) {
      usuario.senha = novaSenha;
      res.json({ message: 'Senha atualizada com sucesso.', usuario });
    } else {
      res.status(403).json({ error: 'Data de nascimento não confere.' });
    }
  } else {
    res.status(404).json({ error: 'Usuário não encontrado.' });
  }
});

// Rota para atualizar o email do usuário (com verificação da data de nascimento)
app.put('/perfil/email', authenticate, (req, res) => {
  const usuario = getCurrentUser(req);
  const { novoEmail, dataNascimento } = req.body;

  if (usuario) {
    // Verifica se a data de nascimento confere com o registro
    if (usuario.dataNascimento === dataNascimento) {
      usuario.email = novoEmail;
      res.json({ message: 'Email atualizado com sucesso.', usuario });
    } else {
      res.status(403).json({ error: 'Data de nascimento não confere.' });
    }
  } else {
    res.status(404).json({ error: 'Usuário não encontrado.' });
  }
});

// Rota para atualizar a data de nascimento (com confirmação de senha)
app.put('/perfil/datanascimento', authenticate, (req, res) => {
  const usuario = getCurrentUser(req);
  const { novaDataNascimento, senha } = req.body;

  if (usuario) {
    // Verifica se a senha confere
    if (usuario.senha === senha) {
      usuario.dataNascimento = novaDataNascimento;
      res.json({ message: 'Data de nascimento atualizada com sucesso.', usuario });
    } else {
      res.status(403).json({ error: 'Senha incorreta.' });
    }
  } else {
    res.status(404).json({ error: 'Usuário não encontrado.' });
  }
});

//LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.send('Erro ao sair.');
    }
    res.send('<h2>Você saiu com sucesso!</h2><a href="/login">Login novamente</a>');
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
