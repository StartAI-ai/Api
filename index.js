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

// Rota para atualizar os dados do usuário
app.put('/usuario/atualizar', async (req, res) => {
  const { email, nome, senha, nova_senha, dataNascimento, dataNascimento_confirmacao } = req.body;

  // Verifica se o email foi fornecido
  if (!email) {
    return res.status(400).json({ error: 'Email é necessário para identificar o usuário.' });
  }

  // Busca o usuário no banco de dados pelo email
  const { data: usuario, error } = await supabase
    .from('Usuarios')
    .select('*')
    .eq('email', email)
    .single();

  // Verifica se o usuário foi encontrado
  if (!usuario) {
    return res.status(404).json({ error: 'Usuário não encontrado.' });
  }

  // Se o usuário deseja alterar nome ou data de nascimento, precisa confirmar a senha
  const updates = {};
  if (nome || dataNascimento) {
    if (!senha) {
      return res.status(400).json({ error: 'A senha de confirmação é necessária para alterar o nome ou a data de nascimento.' });
    }

    // Verifica se a senha confirmada está correta usando Argon2
    const senhaValida = await argon2.verify(usuario.senha, senha);
    if (!senhaValida) {
      return res.status(403).json({ error: 'Senha incorreta. Não foi possível alterar o nome ou a data de nascimento.' });
    }

    if (nome) updates.nome = nome;
    if (dataNascimento) updates.dataNascimento = dataNascimento;
  }

  // Se o usuário deseja alterar o email ou a senha, precisa confirmar a data de nascimento
  if (nova_senha || email !== usuario.email) {
    if (!dataNascimento_confirmacao || dataNascimento_confirmacao !== usuario.dataNascimento) {
      return res.status(403).json({ error: 'Data de nascimento incorreta. Não foi possível alterar o email ou a senha.' });
    }

    if (nova_senha) {
      // Criptografa a nova senha usando Argon2
      const senhaCriptografada = await argon2.hash(nova_senha);
      updates.senha = senhaCriptografada;
    }

    if (email !== usuario.email) {
      updates.email = email;
    }
  }

  // Verifica se há algo para atualizar
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'Nenhuma alteração foi solicitada.' });
  }

  // Atualiza o usuário no banco de dados
  const { error: updateError } = await supabase
    .from('Usuarios')
    .update(updates)
    .eq('email', usuario.email);

  if (updateError) {
    return res.status(500).json({ error: 'Erro ao atualizar os dados do usuário.' });
  }

  res.json({ message: 'Dados do usuário atualizados com sucesso.' });
});



// Rota de logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao sair.' });
    }
    res.json({ message: 'Você saiu com sucesso.' });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
