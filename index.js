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

// Redefinir-Senha
app.post('/redefinir-senha', async (req, res) => {
  const { senha, email, dataNascimento } = req.body;

  // Valida se todos os campos foram preenchidos
  if (!senha || !email || !dataNascimento) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    // Verifica se o usuário existe com o e-mail fornecido
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Verifica se a data de nascimento corresponde
    if (user.dataNascimento !== dataNascimento) {
      return res.status(400).json({ error: 'Data de nascimento inválida.' });
    }

    // Criptografa a nova senha
    const hashedPassword = await argon2.hash(senha);

    // Atualiza a senha do usuário
    const { error: updateError } = await supabase
      .from('Usuario')
      .update({ senha: hashedPassword })
      .eq('id', user.id);

    if (updateError) {
      throw updateError;
    }

    res.status(200).json({ message: 'Senha redefinida com sucesso!' });
  } catch (error) {
    console.error('Erro ao redefinir senha:', error);
    res.status(500).json({ error: 'Erro ao redefinir senha.' });
  }
});

//ROTAS PONTUAÇÃO

//Registrar Pontuação
app.post('/registrar-pontuacao', async (req, res) => {
  const { pontuacao, tempo, id_usuario, id_controle, id_jogo } = req.body;

  // Valida se todos os campos foram preenchidos
  if (!pontuacao || !tempo || !id_usuario || !id_controle || !id_jogo) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    // Verifica se já existe um registro para o usuário, jogo e controle
    const { data: existingRecord, error: fetchError } = await supabase
      .from('Placar')
      .select('*')
      .eq('id_usuario', id_usuario)
      .eq('id_jogo', id_jogo)
      .eq('id_controle', id_controle)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') {
      console.error('Erro ao buscar registro existente:', fetchError);
      return res.status(500).json({ error: 'Erro ao verificar registro existente.' });
    }

    if (existingRecord) {
      // Atualiza o registro existente
      const { error: updateError } = await supabase
        .from('Placar')
        .update({ pontuacao, tempo })
        .eq('id_placar', existingRecord.id_placar);

      if (updateError) {
        console.error('Erro ao atualizar pontuação:', updateError);
        return res.status(500).json({ error: 'Erro ao atualizar pontuação.' });
      }

      // Registro atualizado com sucesso
      return res.status(200).json({
        message: 'Pontuação atualizada com sucesso!',
        pontuacao: { ...existingRecord, pontuacao, tempo },
      });
    } else {
      // Insere a nova pontuação
      const { data, error: insertError } = await supabase
        .from('Placar')
        .insert([{ pontuacao, tempo, id_usuario, id_controle, id_jogo }])
        .select()
        .single();

      if (insertError) {
        console.error('Erro ao registrar pontuação:', insertError);
        return res.status(500).json({ error: 'Erro ao registrar pontuação.' });
      }

      // Registro de pontuação bem-sucedido
      return res.status(201).json({
        message: 'Pontuação registrada com sucesso!',
        pontuacao: data,
      });
    }
  } catch (error) {
    console.error('Erro ao registrar pontuação:', error);
    res.status(500).json({ error: 'Erro ao registrar pontuação.' });
  }
});

// Obter as 3 maiores pontuações e 3 menores tempos com filtros
app.get('/maiores-pontuacoes-menos-tempos', async (req, res) => {
  const { id_jogo, id_controle } = req.query; // Use req.query para GET

  // Valida se os parâmetros foram fornecidos
  if (!id_jogo || !id_controle) {
    return res.status(400).json({ error: 'Os parâmetros id_jogo e id_controle são obrigatórios.' });
  }

  try {
    // Consulta para obter as 3 menores tempos filtrados por id_jogo e id_controle
    const { data: menoresTempos, error: tempoError } = await supabase
      .from('Placar')
      .select('*')
      .eq('id_jogo', id_jogo)
      .eq('id_controle', id_controle)
      .order('tempo', { ascending: true })
      .limit(3);

    if (tempoError) {
      console.error('Erro ao buscar menores tempos:', tempoError);
      return res.status(500).json({ error: 'Erro ao buscar menores tempos.' });
    }

    // Extraindo os IDs dos registros com os menores tempos
    const idsMenoresTempos = menoresTempos.map(item => item.id_placar);

    // Consulta para obter as maiores pontuações entre os menores tempos
    const { data: maioresPontuacoes, error: pontuacaoError } = await supabase
      .from('Placar')
      .select('*')
      .in('id_placar', idsMenoresTempos) // Filtra pelos IDs obtidos
      .order('pontuacao', { ascending: false })
      .limit(3);

    if (pontuacaoError) {
      console.error('Erro ao buscar maiores pontuações:', pontuacaoError);
      return res.status(500).json({ error: 'Erro ao buscar maiores pontuações.' });
    }

    // Extraindo os IDs dos usuários das maiores pontuações
    const idsUsuarios = maioresPontuacoes.map(item => item.id_usuario);

    // Consulta para obter os nomes dos usuários
    const { data: usuarios, error: usuarioError } = await supabase
      .from('Usuario')
      .select('id, nome')
      .in('id', idsUsuarios);

    if (usuarioError) {
      console.error('Erro ao buscar usuários:', usuarioError);
      return res.status(500).json({ error: 'Erro ao buscar usuários.' });
    }

    // Criando um mapeamento de id para nome
    const usuarioMap = {};
    usuarios.forEach(usuario => {
      usuarioMap[usuario.id] = usuario.nome;
    });

    // Adicionando o nome do jogador em maioresPontuacoes
    const maioresPontuacoesComJogador = maioresPontuacoes.map(item => ({
      ...item,
      Jogador: usuarioMap[item.id_usuario] || 'Desconhecido', // Adiciona o nome do jogador
    }));

    // Retorna os resultados
    res.status(200).json({
      message: 'Consulta realizada com sucesso!',
      maioresPontuacoes: maioresPontuacoesComJogador,
    });
  } catch (error) {
    console.error('Erro ao processar a requisição:', error);
    res.status(500).json({ error: 'Erro ao processar a requisição.' });
  }
});

//ROTAS PERFIL

app.get('/usuario/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Busca o usuário pelo ID
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('id', id)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Busca o controle associado ao usuário
    const { data: userControl, error: controlError } = await supabase
      .from('User_controle')
      .select('controle_id')
      .eq('user_id', id)
      .single();

    if (controlError) {
      console.error('Erro ao buscar controle do usuário:', controlError);
      return res.status(500).json({ error: 'Erro ao buscar controle do usuário.' });
    }

    // Remove a senha do objeto do usuário
    const { senha, ...userWithoutPassword } = user;

    // Cria a resposta com os dados do usuário e controle
    const response = {
      ...userWithoutPassword,
      controleId: userControl ? userControl.controle_id : null,
    };

    res.status(200).json({
      message: 'Usuário encontrado com sucesso!',
      user: response,
    });
  } catch (error) {
    console.error('Erro ao obter dados do usuário:', error);
    res.status(500).json({ error: 'Erro ao obter dados do usuário.' });
  }
});

app.get('/usuario/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Busca o usuário pelo ID
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('id', id)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Busca o controle associado ao usuário
    const { data: userControl, error: controlError } = await supabase
      .from('User_controle')
      .select('controle_id')
      .eq('user_id', id)
      .single();

    if (controlError) {
      console.error('Erro ao buscar controle do usuário:', controlError);
      return res.status(500).json({ error: 'Erro ao buscar controle do usuário.' });
    }

    // Cria o objeto de resposta, excluindo a senha
    const { senha, ...userWithoutPassword } = user; // Desestrutura para remover a senha
    const response = {
      ...userWithoutPassword,
      controleId: userControl ? userControl.controle_id : null, // Adiciona controle_id se existir
    };

    res.status(200).json(response);
  } catch (error) {
    console.error('Erro ao obter dados do usuário:', error);
    res.status(500).json({ error: 'Erro ao obter dados do usuário.' });
  }
});

app.delete('/deletar-usuario/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Verifica se o usuário existe
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('id', id)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Deleta as pontuações associadas ao usuário no placar
    const { error: deleteScoresError } = await supabase
      .from('Placar')
      .delete()
      .eq('id_usuario', id);

    if (deleteScoresError) {
      console.error('Erro ao deletar pontuações:', deleteScoresError);
      return res.status(500).json({ error: 'Erro ao deletar pontuações.' });
    }

    // Deleta as referências do controle associado ao usuário
    const { error: deleteControlError } = await supabase
      .from('User_controle')
      .delete()
      .eq('user_id', id);

    if (deleteControlError) {
      console.error('Erro ao deletar controle do usuário:', deleteControlError);
      return res.status(500).json({ error: 'Erro ao deletar controle do usuário.' });
    }

    // Deleta o usuário
    const { error: deleteUserError } = await supabase
      .from('Usuario')
      .delete()
      .eq('id', id);

    if (deleteUserError) {
      console.error('Erro ao deletar usuário:', deleteUserError);
      return res.status(500).json({ error: 'Erro ao deletar usuário.' });
    }

    res.status(200).json({ message: 'Usuário e suas pontuações deletados com sucesso!' });
  } catch (error) {
    console.error('Erro ao deletar usuário:', error);
    res.status(500).json({ error: 'Erro ao deletar usuário.' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
