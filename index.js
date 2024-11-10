const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const argon2 = require('argon2');
const { body, validationResult } = require('express-validator');  // Para validações
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(cors({
  origin: ['https://startai.vercel.app', 'https://startai-startai-ais-projects.vercel.app', 'http://localhost:4200']
}));

app.use(express.json());

// Middleware para validar os dados de entrada (exemplo de validação de campos obrigatórios)
const validateUserRegistration = [
  body('nome').notEmpty().withMessage('Nome de usuário é obrigatório'),
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('senha').isLength({ min: 8 }).withMessage('A senha deve ter no mínimo 8 caracteres'),
  body('dataNascimento').isDate().withMessage('Data de nascimento inválida'),
  body('controle').notEmpty().withMessage('Controle é obrigatório')
];

// Rota para registrar um novo usuário
app.post('/registrar', validateUserRegistration, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });  // Apenas o primeiro erro será retornado
  }

  const { nome, email, senha, dataNascimento, controle } = req.body;

  try {
    // Verifica se já existe um usuário com o mesmo nome (nome)
    const { data: existingUserByName, error: nameCheckError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('nome', nome);

    if (nameCheckError) {
      throw nameCheckError;
    }

    if (existingUserByName.length > 0) {
      return res.status(400).json({ error: 'Este nome de usuário já está em uso.' });
    }

    // Verifica se já existe um usuário com o mesmo email
    const { data: existingUsersByEmail, error: emailCheckError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email);

    if (emailCheckError) {
      throw emailCheckError;
    }

    if (existingUsersByEmail.length > 0) {
      return res.status(400).json({ error: 'Já existe um usuário com este e-mail.' });
    }

    // Criptografa a senha
    const hashedPassword = await argon2.hash(senha);

    // Insere o novo usuário no banco de dados
    const { data: userData, error: userInsertError } = await supabase
      .from('Usuario')
      .insert([{ nome, email, senha: hashedPassword, dataNascimento }])
      .select()
      .single();

    if (userInsertError) {
      throw userInsertError;
    }

    // Associa o controle ao usuário
    const { error: controleError } = await supabase
      .from('User_controle')
      .insert([{ user_id: userData.id, controle_id: controle }]);

    if (controleError) {
      await supabase.from('Usuario').delete().eq('id', userData.id); // Rollback caso falhe
      return res.status(400).json({ error: 'Erro ao associar o controle. Usuário não registrado.' });
    }

    // Remove a senha do objeto antes de retornar ao cliente
    const { senha: _, ...userWithoutPassword } = userData;

    res.status(201).json({ message: 'Usuário registrado com sucesso!', user: userWithoutPassword });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
});

// Rota para login (verifica email e senha)
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(400).json({ error: 'Email não cadastrado.' });
    }

    // Verifica se a senha informada corresponde à armazenada
    const passwordMatch = await argon2.verify(user.senha, senha);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const { data: userControl, error: controlError } = await supabase
    .from('User_controle')
    .select('controle_id')
    .eq('user_id', user.id)
    .single();

    // Remove a senha do objeto de resposta
    const { senha: _, ...userWithoutPassword } = user;

    res.status(200).json({
      message: 'Login bem-sucedido!',
      user: userWithoutPassword,
      controleId: userControl 
    });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
});

// Rota para redefinir senha
app.post('/redefinir-senha', async (req, res) => {
  const { senha, email, dataNascimento } = req.body;

  if (!senha || !email || !dataNascimento) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    const { data: user, error: userError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    if (user.dataNascimento !== dataNascimento) {
      return res.status(400).json({ error: 'Data de nascimento inválida.' });
    }

    const hashedPassword = await argon2.hash(senha);

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
app.get('/maiores-pontuacoes', async (req, res) => {
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

app.put('/atualizar-dados/:id', async (req, res) => {
  const { nome, email, dataNascimento, controle } = req.body; 
  const { id } = req.params;

  // Valida se todos os campos obrigatórios foram preenchidos
  if (!nome || !email || !dataNascimento || controle === undefined) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

   // Verifica se já existe um usuário com o mesmo nome (nome)
    const { data: existingUserByName, error: nameCheckError } = await supabase
    .from('Usuario')
    .select('*')
    .eq('nome', nome)
    .neq('id', id);

    if (nameCheckError) {
      throw nameCheckError;
    }

    if (existingUserByName.length > 0) {
      return res.status(400).json({ error: 'Este nome de usuário já está em uso.' });
    }

    // Verifica se já existe um usuário com o mesmo email
    const { data: existingUsersByEmail, error: emailCheckError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('email', email)
      .neq('id', id);

    if (emailCheckError) {
      throw emailCheckError;
    }

    if (existingUsersByEmail.length > 0) {
      return res.status(400).json({ error: 'Já existe um usuário com este e-mail.' });
    }

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

    // Atualiza os dados do usuário
    const { error: updateError } = await supabase
      .from('Usuario')
      .update({ nome, email, dataNascimento })
      .eq('id', id);

    if (updateError) {
      console.error('Erro ao atualizar dados pessoais:', updateError);
      return res.status(500).json({ error: 'Erro ao atualizar dados pessoais.' });
    }

    // Atualiza o controle associado ao usuário
    const { error: controleError } = await supabase
      .from('User_controle')
      .update({ controle_id: controle })
      .eq('user_id', id);

    if (controleError) {
      console.error('Erro ao atualizar controle:', controleError);
      return res.status(500).json({ error: 'Erro ao atualizar controle.' });
    }

    // Busca os dados atualizados do usuário
    const { data: updatedUser, error: updatedUserError } = await supabase
      .from('Usuario')
      .select('*')
      .eq('id', id)
      .single();

    // Busca o controle atualizado
    const { data: userControle, error: userControleError } = await supabase
      .from('User_controle')
      .select('controle_id')
      .eq('user_id', id)
      .single();

    if (updatedUserError || !updatedUser || userControleError || !userControle) {
      return res.status(500).json({ error: 'Erro ao recuperar dados atualizados.' });
    }

    // Remove a senha do usuário se existir
    const { senha, ...userWithoutPassword } = updatedUser;

    res.status(200).json({
      message: 'Dados pessoais e controle atualizados com sucesso!',
      user: userWithoutPassword,
      controleId: userControle.controle_id // Retorna o controle_id, se existir
    });
  } catch (error) {
    console.error('Erro ao atualizar dados pessoais:', error);
    res.status(500).json({ error: 'Erro ao atualizar dados pessoais.' });
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
