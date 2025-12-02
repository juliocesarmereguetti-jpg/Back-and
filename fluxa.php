<?php
// ============================================
// CONFIGURAÇÕES E INICIALIZAÇÃO
// ============================================
session_start();

// Configurações do banco de dados
define('DB_HOST', 'localhost');
define('DB_NAME', 'fluxa_financeiro');
define('DB_USER', 'root');
define('DB_PASS', '');

// Conexão com banco de dados
function getDatabaseConnection() {
    static $conn = null;
    
    if ($conn === null) {
        try {
            $conn = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8",
                DB_USER,
                DB_PASS
            );
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            die("Erro de conexão: " . $e->getMessage());
        }
    }
    
    return $conn;
}

// Funções auxiliares
function validarDados($dados, $filtros = []) {
    $dados_validados = [];
    
    foreach ($filtros as $campo => $config) {
        if (isset($dados[$campo]) && $dados[$campo] !== '') {
            $valor = filter_var(trim($dados[$campo]), $config['filtro']);
            
            if ($valor === false || $valor === null) {
                $_SESSION['erro'] = "Campo '$campo' inválido!";
                return false;
            }
            
            $dados_validados[$campo] = htmlspecialchars($valor, ENT_QUOTES, 'UTF-8');
        } elseif ($config['required'] ?? false) {
            $_SESSION['erro'] = "Campo '$campo' é obrigatório!";
            return false;
        }
    }
    
    return $dados_validados;
}

function criptografarSenha($senha) {
    return password_hash($senha, PASSWORD_BCRYPT);
}

function verificarSenha($senha, $hash) {
    return password_verify($senha, $hash);
}

function verificarLogin() {
    if (!isset($_SESSION['usuario_id'])) {
        header("Location: ?page=login");
        exit();
    }
    return $_SESSION['usuario_id'];
}

function obterNomeUsuario($usuario_id) {
    try {
        $db = getDatabaseConnection();
        $stmt = $db->prepare("SELECT nome_completo FROM usuarios WHERE id = ?");
        $stmt->execute([$usuario_id]);
        return $stmt->fetchColumn() ?: "Usuário";
    } catch(PDOException $e) {
        return "Usuário";
    }
}

function formatarMoeda($valor) {
    return 'R$ ' . number_format($valor, 2, ',', '.');
}

function gerarIniciais($nome) {
    $iniciais = '';
    $palavras = explode(' ', $nome);
    
    foreach ($palavras as $palavra) {
        if (strlen($palavra) > 0) {
            $iniciais .= strtoupper(substr($palavra, 0, 1));
            if (strlen($iniciais) >= 2) break;
        }
    }
    
    return $iniciais;
}

// ============================================
// PROCESSAMENTO DAS PÁGINAS
// ============================================
$page = $_GET['page'] ?? 'login';
$mensagem_sucesso = $_SESSION['sucesso'] ?? '';
$mensagem_erro = $_SESSION['erro'] ?? '';

// Limpa mensagens após pegar
unset($_SESSION['sucesso']);
unset($_SESSION['erro']);

// Processamento do login
if ($page == 'login' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $filtros = [
        'email' => ['filtro' => FILTER_VALIDATE_EMAIL, 'required' => true],
        'senha' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true]
    ];
    
    $dados = validarDados($_POST, $filtros);
    
    if ($dados) {
        try {
            $db = getDatabaseConnection();
            $stmt = $db->prepare("SELECT id, nome_completo, senha FROM usuarios WHERE email = ?");
            $stmt->execute([$dados['email']]);
            
            if ($stmt->rowCount() == 1) {
                $usuario = $stmt->fetch();
                
                if (verificarSenha($dados['senha'], $usuario['senha'])) {
                    $_SESSION['usuario_id'] = $usuario['id'];
                    $_SESSION['sucesso'] = "Login realizado com sucesso!";
                    header("Location: ?page=dashboard");
                    exit();
                } else {
                    $mensagem_erro = "E-mail ou senha incorretos!";
                }
            } else {
                $mensagem_erro = "E-mail ou senha incorretos!";
            }
        } catch(PDOException $e) {
            $mensagem_erro = "Erro no sistema: " . $e->getMessage();
        }
    } else {
        $mensagem_erro = $_SESSION['erro'] ?? "Dados inválidos!";
        unset($_SESSION['erro']);
    }
}

// Processamento do cadastro
if ($page == 'register' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $filtros = [
        'nome_completo' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'cpf' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'telefone' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'email' => ['filtro' => FILTER_VALIDATE_EMAIL, 'required' => true],
        'senha' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'confirmar_senha' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true]
    ];
    
    $dados = validarDados($_POST, $filtros);
    
    if ($dados) {
        if ($dados['senha'] !== $dados['confirmar_senha']) {
            $mensagem_erro = "As senhas não coincidem!";
        } else {
            try {
                $db = getDatabaseConnection();
                
                // Verifica se email ou CPF já existem
                $stmt = $db->prepare("SELECT id FROM usuarios WHERE email = ? OR cpf = ?");
                $stmt->execute([$dados['email'], $dados['cpf']]);
                
                if ($stmt->rowCount() > 0) {
                    $mensagem_erro = "E-mail ou CPF já cadastrado!";
                } else {
                    $senha_hash = criptografarSenha($dados['senha']);
                    
                    $stmt = $db->prepare("INSERT INTO usuarios (nome_completo, cpf, telefone, email, senha) VALUES (?, ?, ?, ?, ?)");
                    
                    if ($stmt->execute([$dados['nome_completo'], $dados['cpf'], $dados['telefone'], $dados['email'], $senha_hash])) {
                        $_SESSION['sucesso'] = "Cadastro realizado com sucesso! Faça login.";
                        header("Location: ?page=login");
                        exit();
                    } else {
                        $mensagem_erro = "Erro ao cadastrar. Tente novamente.";
                    }
                }
            } catch(PDOException $e) {
                $mensagem_erro = "Erro no sistema: " . $e->getMessage();
            }
        }
    } else {
        $mensagem_erro = $_SESSION['erro'] ?? "Preencha todos os campos corretamente!";
        unset($_SESSION['erro']);
    }
}

// Processamento da adição de transação
if ($page == 'adicionar' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $usuario_id = verificarLogin();
    
    $filtros = [
        'descricao' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'valor' => ['filtro' => FILTER_VALIDATE_FLOAT, 'required' => true],
        'categoria' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'tipo' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'data_transacao' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true]
    ];
    
    $dados = validarDados($_POST, $filtros);
    
    if ($dados) {
        try {
            $db = getDatabaseConnection();
            
            $stmt = $db->prepare("INSERT INTO transacoes (usuario_id, tipo, descricao, valor, categoria, data_transacao, observacoes) VALUES (?, ?, ?, ?, ?, ?, ?)");
            
            $sucesso = $stmt->execute([
                $usuario_id,
                $dados['tipo'],
                $dados['descricao'],
                $dados['valor'],
                $dados['categoria'],
                $dados['data_transacao'],
                $_POST['observacoes'] ?? ''
            ]);
            
            if ($sucesso) {
                $_SESSION['sucesso'] = "Transação adicionada com sucesso!";
                header("Location: ?page=adicionar");
                exit();
            } else {
                $mensagem_erro = "Erro ao adicionar transação.";
            }
        } catch(PDOException $e) {
            $mensagem_erro = "Erro: " . $e->getMessage();
        }
    } else {
        $mensagem_erro = $_SESSION['erro'] ?? "Preencha todos os campos obrigatórios!";
        unset($_SESSION['erro']);
    }
}

// Processamento da exclusão de transação
if ($page == 'excluir' && isset($_GET['action']) && $_GET['action'] == 'delete') {
    $usuario_id = verificarLogin();
    
    if (isset($_GET['id'])) {
        try {
            $db = getDatabaseConnection();
            $stmt = $db->prepare("DELETE FROM transacoes WHERE id = ? AND usuario_id = ?");
            $stmt->execute([$_GET['id'], $usuario_id]);
            
            $_SESSION['sucesso'] = "Transação excluída com sucesso!";
            header("Location: ?page=excluir");
            exit();
        } catch(PDOException $e) {
            $mensagem_erro = "Erro ao excluir transação: " . $e->getMessage();
        }
    }
}

// Processamento da atualização de transação
if ($page == 'editar' && $_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['atualizar'])) {
    $usuario_id = verificarLogin();
    
    $filtros = [
        'id' => ['filtro' => FILTER_VALIDATE_INT, 'required' => true],
        'descricao' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true],
        'valor' => ['filtro' => FILTER_VALIDATE_FLOAT, 'required' => true],
        'categoria' => ['filtro' => FILTER_SANITIZE_STRING, 'required' => true]
    ];
    
    $dados = validarDados($_POST, $filtros);
    
    if ($dados) {
        try {
            $db = getDatabaseConnection();
            
            $stmt = $db->prepare("UPDATE transacoes SET descricao = ?, valor = ?, categoria = ?, data_transacao = ?, observacoes = ? WHERE id = ? AND usuario_id = ?");
            
            $sucesso = $stmt->execute([
                $dados['descricao'],
                $dados['valor'],
                $dados['categoria'],
                $_POST['data_transacao'],
                $_POST['observacoes'] ?? '',
                $dados['id'],
                $usuario_id
            ]);
            
            if ($sucesso) {
                $_SESSION['sucesso'] = "Transação atualizada com sucesso!";
                header("Location: ?page=editar");
                exit();
            } else {
                $mensagem_erro = "Erro ao atualizar transação.";
            }
        } catch(PDOException $e) {
            $mensagem_erro = "Erro: " . $e->getMessage();
        }
    } else {
        $mensagem_erro = $_SESSION['erro'] ?? "Preencha todos os campos obrigatórios!";
        unset($_SESSION['erro']);
    }
}

// Processamento do logout
if ($page == 'logout') {
    session_destroy();
    header("Location: ?page=login");
    exit();
}

// ============================================
// CONSULTAS AO BANCO DE DADOS
// ============================================
$usuario_id = $_SESSION['usuario_id'] ?? null;
$nome_usuario = '';
$iniciais = '';

if ($usuario_id) {
    $nome_usuario = obterNomeUsuario($usuario_id);
    $iniciais = gerarIniciais($nome_usuario);
}

// Consultas para dashboard
$total_receitas = 0;
$total_despesas = 0;
$saldo = 0;
$transacoes_recentes = [];
$transacoes_todas = [];

if ($usuario_id) {
    try {
        $db = getDatabaseConnection();
        
        // Total de receitas
        $stmt = $db->prepare("SELECT COALESCE(SUM(valor), 0) FROM transacoes WHERE usuario_id = ? AND tipo = 'receita'");
        $stmt->execute([$usuario_id]);
        $total_receitas = $stmt->fetchColumn();
        
        // Total de despesas
        $stmt = $db->prepare("SELECT COALESCE(SUM(valor), 0) FROM transacoes WHERE usuario_id = ? AND tipo = 'despesa'");
        $stmt->execute([$usuario_id]);
        $total_despesas = $stmt->fetchColumn();
        
        // Saldo
        $saldo = $total_receitas - $total_despesas;
        
        // Transações recentes (5 últimas)
        $stmt = $db->prepare("SELECT * FROM transacoes WHERE usuario_id = ? ORDER BY data_transacao DESC, id DESC LIMIT 5");
        $stmt->execute([$usuario_id]);
        $transacoes_recentes = $stmt->fetchAll();
        
        // Todas as transações para extrato
        $stmt = $db->prepare("SELECT * FROM transacoes WHERE usuario_id = ? ORDER BY data_transacao DESC, id DESC");
        $stmt->execute([$usuario_id]);
        $transacoes_todas = $stmt->fetchAll();
        
        // Transação específica para edição
        $transacao_editar = null;
        if ($page == 'editar' && isset($_GET['id'])) {
            $stmt = $db->prepare("SELECT * FROM transacoes WHERE id = ? AND usuario_id = ?");
            $stmt->execute([$_GET['id'], $usuario_id]);
            $transacao_editar = $stmt->fetch();
        }
        
    } catch(PDOException $e) {
        $mensagem_erro = "Erro ao carregar dados: " . $e->getMessage();
    }
}

// ============================================
// HTML - CABEÇALHO
// ============================================
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fluxa - Gestão Financeira Inteligente</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4361ee;
            --secondary-color: #3f37c9;
            --success-color: #4cc9f0;
            --danger-color: #f72585;
            --warning-color: #f8961e;
            --info-color: #4895ef;
            --light-color: #f8f9fa;
            --dark-color: #212529;
            --gray-color: #6c757d;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f7fb;
            color: #333;
        }
        
        .auth-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%);
        }
        
        .auth-card {
            background-color: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            padding: 2rem;
            width: 100%;
            max-width: 400px;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .logo h1 {
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        
        .logo p {
            color: var(--gray-color);
            font-size: 0.9rem;
        }
        
        .form-control {
            border-radius: 10px;
            padding: 0.75rem 1rem;
            border: 1px solid #e1e5eb;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(67, 97, 238, 0.25);
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 10px;
            padding: 0.75rem;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .auth-link {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        .auth-link:hover {
            color: var(--secondary-color);
            text-decoration: underline;
        }
        
        .dashboard-container {
            min-height: 100vh;
            background-color: #f5f7fb;
        }
        
        .sidebar {
            background-color: white;
            min-height: 100vh;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.05);
            position: fixed;
            width: 250px;
            z-index: 1000;
        }
        
        .sidebar-logo {
            padding: 1.5rem 1rem;
            border-bottom: 1px solid #e1e5eb;
        }
        
        .sidebar-nav {
            padding: 1rem 0;
        }
        
        .nav-item {
            margin-bottom: 0.5rem;
        }
        
        .nav-link {
            color: var(--gray-color);
            padding: 0.75rem 1.5rem;
            border-radius: 0;
            display: flex;
            align-items: center;
            transition: all 0.3s;
        }
        
        .nav-link i {
            margin-right: 0.75rem;
            width: 20px;
            text-align: center;
        }
        
        .nav-link:hover, .nav-link.active {
            color: var(--primary-color);
            background-color: rgba(67, 97, 238, 0.1);
            border-right: 3px solid var(--primary-color);
        }
        
        .main-content {
            margin-left: 250px;
            padding: 2rem;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        .page-title {
            font-weight: 600;
            color: var(--dark-color);
            margin-bottom: 0;
        }
        
        .user-profile {
            display: flex;
            align-items: center;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--primary-color);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-right: 0.75rem;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            margin-bottom: 1.5rem;
        }
        
        .card-header {
            background-color: white;
            border-bottom: 1px solid #e1e5eb;
            padding: 1.25rem 1.5rem;
            border-radius: 15px 15px 0 0 !important;
        }
        
        .card-title {
            font-weight: 600;
            margin-bottom: 0;
            color: var(--dark-color);
        }
        
        .balance-card {
            background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
        }
        
        .balance-amount {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .balance-label {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .stats-card {
            text-align: center;
            padding: 1.5rem;
        }
        
        .stats-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        
        .stats-label {
            font-size: 0.85rem;
            color: var(--gray-color);
            margin-bottom: 0.5rem;
        }
        
        .stats-change {
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .positive {
            color: #2ecc71;
        }
        
        .negative {
            color: #e74c3c;
        }
        
        .transaction-item {
            display: flex;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid #e1e5eb;
        }
        
        .transaction-item:last-child {
            border-bottom: none;
        }
        
        .transaction-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            color: white;
        }
        
        .transaction-details {
            flex: 1;
        }
        
        .transaction-name {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .transaction-category {
            font-size: 0.85rem;
            color: var(--gray-color);
        }
        
        .transaction-amount {
            font-weight: 600;
        }
        
        .income {
            color: #2ecc71;
        }
        
        .expense {
            color: #e74c3c;
        }
        
        .form-section {
            margin-bottom: 1.5rem;
        }
        
        .form-label {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .btn-group-toggle .btn {
            border-radius: 10px;
            padding: 0.5rem 1rem;
        }
        
        .btn-outline-primary.active {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .alert {
            border-radius: 10px;
            border: none;
            margin-bottom: 1.5rem;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .table {
            background-color: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .table th {
            border-top: none;
            font-weight: 600;
            color: var(--dark-color);
            background-color: #f8f9fa;
        }
        
        .btn-sm {
            padding: 0.25rem 0.5rem;
            font-size: 0.875rem;
            border-radius: 8px;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                transform: translateX(-100%);
                transition: transform 0.3s;
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <?php if ($mensagem_sucesso): ?>
        <div class="alert alert-success alert-dismissible fade show m-3" role="alert">
            <?php echo $mensagem_sucesso; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    
    <?php if ($mensagem_erro): ?>
        <div class="alert alert-danger alert-dismissible fade show m-3" role="alert">
            <?php echo $mensagem_erro; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    
    <?php if ($usuario_id): ?>
        <!-- DASHBOARD LAYOUT -->
        <div class="dashboard-container">
            <!-- Sidebar -->
            <div class="sidebar">
                <div class="sidebar-logo">
                    <h3>fluxa</h3>
                </div>
                <ul class="sidebar-nav nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link <?php echo $page == 'dashboard' ? 'active' : ''; ?>" href="?page=dashboard">
                            <i class="fas fa-home"></i> Início
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $page == 'extrato' ? 'active' : ''; ?>" href="?page=extrato">
                            <i class="fas fa-file-alt"></i> Extrato
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $page == 'adicionar' ? 'active' : ''; ?>" href="?page=adicionar">
                            <i class="fas fa-plus-circle"></i> Adicionar
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $page == 'editar' ? 'active' : ''; ?>" href="?page=editar">
                            <i class="fas fa-edit"></i> Editar
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $page == 'excluir' ? 'active' : ''; ?>" href="?page=excluir">
                            <i class="fas fa-trash"></i> Excluir
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-danger" href="?page=logout">
                            <i class="fas fa-sign-out-alt"></i> Sair
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="main-content">
                <?php if ($page == 'dashboard'): ?>
                    <!-- DASHBOARD -->
                    <div class="header">
                        <h1 class="page-title">Dashboard</h1>
                        <div class="user-profile">
                            <div class="user-avatar"><?php echo $iniciais; ?></div>
                            <span><?php echo htmlspecialchars($nome_usuario); ?></span>
                        </div>
                    </div>
                    
                    <div class="card balance-card">
                        <div class="balance-label">Saldo Disponível</div>
                        <div class="balance-amount"><?php echo formatarMoeda($saldo); ?></div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card stats-card">
                                <div class="stats-value"><?php echo formatarMoeda($total_receitas); ?></div>
                                <div class="stats-label">Receitas</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card">
                                <div class="stats-value"><?php echo formatarMoeda($total_despesas); ?></div>
                                <div class="stats-label">Despesas</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card">
                                <div class="stats-value"><?php echo count($transacoes_todas); ?></div>
                                <div class="stats-label">Transações</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card">
                                <div class="stats-value"><?php echo $saldo > 0 ? '+'.formatarMoeda($saldo) : formatarMoeda($saldo); ?></div>
                                <div class="stats-label">Resultado</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title">Transações recentes</h5>
                        </div>
                        <div class="card-body">
                            <?php if (count($transacoes_recentes) > 0): ?>
                                <?php foreach ($transacoes_recentes as $transacao): ?>
                                    <div class="transaction-item">
                                        <div class="transaction-icon" style="background-color: <?php echo $transacao['tipo'] == 'receita' ? '#2ecc71' : '#e74c3c'; ?>;">
                                            <i class="fas <?php echo $transacao['tipo'] == 'receita' ? 'fa-money-bill-wave' : 'fa-shopping-cart'; ?>"></i>
                                        </div>
                                        <div class="transaction-details">
                                            <div class="transaction-name"><?php echo htmlspecialchars($transacao['descricao']); ?></div>
                                            <div class="transaction-category"><?php echo htmlspecialchars($transacao['categoria']); ?> • <?php echo date('d/m/Y', strtotime($transacao['data_transacao'])); ?></div>
                                        </div>
                                        <div class="transaction-amount <?php echo $transacao['tipo'] == 'receita' ? 'income' : 'expense'; ?>">
                                            <?php echo ($transacao['tipo'] == 'receita' ? '+' : '-') . formatarMoeda($transacao['valor']); ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <p class="text-center text-muted">Nenhuma transação encontrada.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                <?php elseif ($page == 'extrato'): ?>
                    <!-- EXTRATO -->
                    <div class="header">
                        <h1 class="page-title">Extrato</h1>
                        <div class="user-profile">
                            <div class="user-avatar"><?php echo $iniciais; ?></div>
                            <span><?php echo htmlspecialchars($nome_usuario); ?></span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title">Todas as transações</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Data</th>
                                            <th>Descrição</th>
                                            <th>Categoria</th>
                                            <th>Tipo</th>
                                            <th class="text-end">Valor</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (count($transacoes_todas) > 0): ?>
                                            <?php foreach ($transacoes_todas as $transacao): ?>
                                                <tr>
                                                    <td><?php echo date('d/m/Y', strtotime($transacao['data_transacao'])); ?></td>
                                                    <td><?php echo htmlspecialchars($transacao['descricao']); ?></td>
                                                    <td><?php echo htmlspecialchars($transacao['categoria']); ?></td>
                                                    <td>
                                                        <span class="badge bg-<?php echo $transacao['tipo'] == 'receita' ? 'success' : 'danger'; ?>">
                                                            <?php echo $transacao['tipo'] == 'receita' ? 'Receita' : 'Despesa'; ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-end <?php echo $transacao['tipo'] == 'receita' ? 'text-success' : 'text-danger'; ?>">
                                                        <?php echo ($transacao['tipo'] == 'receita' ? '+' : '-') . formatarMoeda($transacao['valor']); ?>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <tr>
                                                <td colspan="5" class="text-center text-muted">Nenhuma transação encontrada.</td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                <?php elseif ($page == 'adicionar'): ?>
                    <!-- ADICIONAR TRANSAÇÃO -->
                    <div class="header">
                        <h1 class="page-title">Nova Transação</h1>
                        <div class="user-profile">
                            <div class="user-avatar"><?php echo $iniciais; ?></div>
                            <span><?php echo htmlspecialchars($nome_usuario); ?></span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-body">
                            <form method="POST" action="?page=adicionar">
                                <div class="form-section">
                                    <label class="form-label">Tipo de transação *</label>
                                    <div class="btn-group btn-group-toggle w-100" data-toggle="buttons">
                                        <label class="btn btn-outline-primary <?php echo !isset($_POST['tipo']) || $_POST['tipo'] == 'despesa' ? 'active' : ''; ?>">
                                            <input type="radio" name="tipo" value="despesa" <?php echo !isset($_POST['tipo']) || $_POST['tipo'] == 'despesa' ? 'checked' : ''; ?>> Despesa
                                        </label>
                                        <label class="btn btn-outline-primary <?php echo isset($_POST['tipo']) && $_POST['tipo'] == 'receita' ? 'active' : ''; ?>">
                                            <input type="radio" name="tipo" value="receita" <?php echo isset($_POST['tipo']) && $_POST['tipo'] == 'receita' ? 'checked' : ''; ?>> Receita
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="form-section">
                                    <label for="descricao" class="form-label">Descrição *</label>
                                    <input type="text" class="form-control" id="descricao" name="descricao" 
                                           value="<?php echo htmlspecialchars($_POST['descricao'] ?? ''); ?>" 
                                           placeholder="Ex: Supermercado, Salário, etc." required>
                                </div>
                                
                                <div class="form-section">
                                    <label for="valor" class="form-label">Valor *</label>
                                    <input type="number" class="form-control" id="valor" name="valor" 
                                           value="<?php echo htmlspecialchars($_POST['valor'] ?? ''); ?>" 
                                           placeholder="0.00" step="0.01" min="0.01" required>
                                </div>
                                
                                <div class="form-section">
                                    <label for="categoria" class="form-label">Categoria *</label>
                                    <select class="form-control" id="categoria" name="categoria" required>
                                        <option value="">Selecione uma categoria</option>
                                        <option value="Alimentação" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Alimentação' ? 'selected' : ''; ?>>Alimentação</option>
                                        <option value="Transporte" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Transporte' ? 'selected' : ''; ?>>Transporte</option>
                                        <option value="Lazer" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Lazer' ? 'selected' : ''; ?>>Lazer</option>
                                        <option value="Saúde" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Saúde' ? 'selected' : ''; ?>>Saúde</option>
                                        <option value="Educação" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Educação' ? 'selected' : ''; ?>>Educação</option>
                                        <option value="Salário" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Salário' ? 'selected' : ''; ?>>Salário</option>
                                        <option value="Investimentos" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Investimentos' ? 'selected' : ''; ?>>Investimentos</option>
                                        <option value="Moradia" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Moradia' ? 'selected' : ''; ?>>Moradia</option>
                                        <option value="Outros" <?php echo isset($_POST['categoria']) && $_POST['categoria'] == 'Outros' ? 'selected' : ''; ?>>Outros</option>
                                    </select>
                                </div>
                                
                                <div class="form-section">
                                    <label for="data_transacao" class="form-label">Data *</label>
                                    <input type="date" class="form-control" id="data_transacao" name="data_transacao" 
                                           value="<?php echo htmlspecialchars($_POST['data_transacao'] ?? date('Y-m-d')); ?>" required>
                                </div>
                                
                                <div class="form-section">
                                    <label for="observacoes" class="form-label">Observações</label>
                                    <textarea class="form-control" id="observacoes" name="observacoes" rows="3" 
                                              placeholder="Observações adicionais (opcional)"><?php echo htmlspecialchars($_POST['observacoes'] ?? ''); ?></textarea>
                                </div>
                                
                                <button type="submit" class="btn btn-primary w-100">Salvar Transação</button>
                            </form>
                        </div>
                    </div>
                    
                <?php elseif ($page == 'editar'): ?>
                    <!-- EDITAR TRANSAÇÃO -->
                    <div class="header">
                        <h1 class="page-title">Editar Transação</h1>
                        <div class="user-profile">
                            <div class="user-avatar"><?php echo $iniciais; ?></div>
                            <span><?php echo htmlspecialchars($nome_usuario); ?></span>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header">
                                    <h5 class="card-title">Selecione uma transação</h5>
                                </div>
                                <div class="card-body">
                                    <?php if (count($transacoes_todas) > 0): ?>
                                        <?php foreach ($transacoes_todas as $transacao): ?>
                                            <a href="?page=editar&id=<?php echo $transacao['id']; ?>" 
                                               class="d-block p-2 border-bottom text-decoration-none <?php echo isset($transacao_editar['id']) && $transacao_editar['id'] == $transacao['id'] ? 'bg-light' : ''; ?>">
                                                <div class="fw-bold"><?php echo htmlspecialchars($transacao['descricao']); ?></div>
                                                <small class="text-muted"><?php echo formatarMoeda($transacao['valor']); ?> • <?php echo date('d/m/Y', strtotime($transacao['data_transacao'])); ?></small>
                                            </a>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <p class="text-center text-muted">Nenhuma transação encontrada.</p>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-8">
                            <?php if ($transacao_editar): ?>
                                <div class="card">
                                    <div class="card-header">
                                        <h5 class="card-title">Editar: <?php echo htmlspecialchars($transacao_editar['descricao']); ?></h5>
                                    </div>
                                    <div class="card-body">
                                        <form method="POST" action="?page=editar">
                                            <input type="hidden" name="id" value="<?php echo $transacao_editar['id']; ?>">
                                            
                                            <div class="form-section">
                                                <label class="form-label">Tipo de transação *</label>
                                                <div class="btn-group btn-group-toggle w-100" data-toggle="buttons">
                                                    <label class="btn btn-outline-primary <?php echo $transacao_editar['tipo'] == 'despesa' ? 'active' : ''; ?>">
                                                        <input type="radio" name="tipo" value="despesa" <?php echo $transacao_editar['tipo'] == 'despesa' ? 'checked' : ''; ?>> Despesa
                                                    </label>
                                                    <label class="btn btn-outline-primary <?php echo $transacao_editar['tipo'] == 'receita' ? 'active' : ''; ?>">
                                                        <input type="radio" name="tipo" value="receita" <?php echo $transacao_editar['tipo'] == 'receita' ? 'checked' : ''; ?>> Receita
                                                    </label>
                                                </div>
                                            </div>
                                            
                                            <div class="mb-3">
                                                <label class="form-label">Descrição *</label>
                                                <input type="text" class="form-control" name="descricao" 
                                                       value="<?php echo htmlspecialchars($transacao_editar['descricao']); ?>" required>
                                            </div>
                                            
                                            <div class="mb-3">
                                                <label class="form-label">Valor *</label>
                                                <input type="number" step="0.01" min="0.01" class="form-control" name="valor" 
                                                       value="<?php echo $transacao_editar['valor']; ?>" required>
                                            </div>
                                            
                                            <div class="mb-3">
                                                <label class="form-label">Categoria *</label>
                                                <select class="form-control" name="categoria" required>
                                                    <option value="Alimentação" <?php echo $transacao_editar['categoria'] == 'Alimentação' ? 'selected' : ''; ?>>Alimentação</option>
                                                    <option value="Transporte" <?php echo $transacao_editar['categoria'] == 'Transporte' ? 'selected' : ''; ?>>Transporte</option>
                                                    <option value="Lazer" <?php echo $transacao_editar['categoria'] == 'Lazer' ? 'selected' : ''; ?>>Lazer</option>
                                                    <option value="Saúde" <?php echo $transacao_editar['categoria'] == 'Saúde' ? 'selected' : ''; ?>>Saúde</option>
                                                    <option value="Educação" <?php echo $transacao_editar['categoria'] == 'Educação' ? 'selected' : ''; ?>>Educação</option>
                                                    <option value="Salário" <?php echo $transacao_editar['categoria'] == 'Salário' ? 'selected' : ''; ?>>Salário</option>
                                                    <option value="Investimentos" <?php echo $transacao_editar['categoria'] == 'Investimentos' ? 'selected' : ''; ?>>Investimentos</option>
                                                    <option value="Moradia" <?php echo $transacao_editar['categoria'] == 'Moradia' ? 'selected' : ''; ?>>Moradia</option>
                                                    <option value="Outros" <?php echo $transacao_editar['categoria'] == 'Outros' ? 'selected' : ''; ?>>Outros</option>
                                                </select>
                                            </div>
                                            
                                            <div class="mb-3">
                                                <label class="form-label">Data *</label>
                                                <input type="date" class="form-control" name="data_transacao" 
                                                       value="<?php echo $transacao_editar['data_transacao']; ?>" required>
                                            </div>
                                            
                                            <div class="mb-3">
                                                <label class="form-label">Observações</label>
                                                <textarea class="form-control" name="observacoes" rows="3"><?php echo htmlspecialchars($transacao_editar['observacoes']); ?></textarea>
                                            </div>
                                            
                                            <button type="submit" name="atualizar" class="btn btn-primary">Atualizar Transação</button>
                                        </form>
                                    </div>
                                </div>
                            <?php else: ?>
                                <div class="card">
                                    <div class="card-body text-center">
                                        <i class="fas fa-edit fa-3x text-muted mb-3"></i>
                                        <h5>Selecione uma transação para editar</h5>
                                        <p class="text-muted">Escolha uma transação na lista ao lado para editar seus dados.</p>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                <?php elseif ($page == 'excluir'): ?>
                    <!-- EXCLUIR TRANSAÇÃO -->
                    <div class="header">
                        <h1 class="page-title">Excluir Transação</h1>
                        <div class="user-profile">
                            <div class="user-avatar"><?php echo $iniciais; ?></div>
                            <span><?php echo htmlspecialchars($nome_usuario); ?></span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title">Transações</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Data</th>
                                            <th>Descrição</th>
                                            <th>Categoria</th>
                                            <th>Tipo</th>
                                            <th class="text-end">Valor</th>
                                            <th class="text-center">Ações</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (count($transacoes_todas) > 0): ?>
                                            <?php foreach ($transacoes_todas as $transacao): ?>
                                                <tr>
                                                    <td><?php echo date('d/m/Y', strtotime($transacao['data_transacao'])); ?></td>
                                                    <td><?php echo htmlspecialchars($transacao['descricao']); ?></td>
                                                    <td><?php echo htmlspecialchars($transacao['categoria']); ?></td>
                                                    <td>
                                                        <span class="badge bg-<?php echo $transacao['tipo'] == 'receita' ? 'success' : 'danger'; ?>">
                                                            <?php echo $transacao['tipo'] == 'receita' ? 'Receita' : 'Despesa'; ?>
                                                        </span>
                                                    </td>
                                                    <td class="text-end <?php echo $transacao['tipo'] == 'receita' ? 'text-success' : 'text-danger'; ?>">
                                                        <?php echo ($transacao['tipo'] == 'receita' ? '+' : '-') . formatarMoeda($transacao['valor']); ?>
                                                    </td>
                                                    <td class="text-center">
                                                        <a href="?page=excluir&action=delete&id=<?php echo $transacao['id']; ?>" 
                                                           class="btn btn-sm btn-outline-danger"
                                                           onclick="return confirm('Tem certeza que deseja excluir esta transação?')">
                                                            <i class="fas fa-trash"></i> Excluir
                                                        </a>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <tr>
                                                <td colspan="6" class="text-center text-muted">Nenhuma transação encontrada.</td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                <?php endif; ?>
            </div>
        </div>
        
    <?php else: ?>
        <!-- TELAS DE AUTENTICAÇÃO -->
        <?php if ($page == 'login'): ?>
            <!-- LOGIN -->
            <div class="auth-container">
                <div class="auth-card">
                    <div class="logo">
                        <h1>fluxa</h1>
                        <p>Gestão financeira inteligente</p>
                    </div>
                    
                    <form method="POST" action="?page=login">
                        <div class="mb-3">
                            <label for="email" class="form-label">E-mail *</label>
                            <input type="email" class="form-control" id="email" name="email" 
                                   value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" 
                                   placeholder="seu@email.com" required>
                        </div>
                        <div class="mb-3">
                            <label for="senha" class="form-label">Senha *</label>
                            <input type="password" class="form-control" id="senha" name="senha" 
                                   placeholder="Digite sua senha" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100 mb-3">Entrar</button>
                        <div class="text-center">
                            <span>Não tem uma conta? </span><a href="?page=register" class="auth-link">Criar conta</a>
                        </div>
                    </form>
                </div>
            </div>
            
        <?php elseif ($page == 'register'): ?>
            <!-- CADASTRO -->
            <div class="auth-container">
                <div class="auth-card">
                    <div class="logo">
                        <h1>Criar nova conta</h1>
                    </div>
                    
                    <form method="POST" action="?page=register">
                        <div class="mb-3">
                            <label for="nome_completo" class="form-label">Nome completo *</label>
                            <input type="text" class="form-control" id="nome_completo" name="nome_completo" 
                                   value="<?php echo htmlspecialchars($_POST['nome_completo'] ?? ''); ?>" 
                                   placeholder="Digite seu nome completo" required>
                        </div>
                        <div class="mb-3">
                            <label for="cpf" class="form-label">CPF *</label>
                            <input type="text" class="form-control" id="cpf" name="cpf" 
                                   value="<?php echo htmlspecialchars($_POST['cpf'] ?? ''); ?>" 
                                   placeholder="000.000.000-00" required>
                        </div>
                        <div class="mb-3">
                            <label for="telefone" class="form-label">Telefone *</label>
                            <input type="tel" class="form-control" id="telefone" name="telefone" 
                                   value="<?php echo htmlspecialchars($_POST['telefone'] ?? ''); ?>" 
                                   placeholder="(00) 00000-0000" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">E-mail *</label>
                            <input type="email" class="form-control" id="email" name="email" 
                                   value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" 
                                   placeholder="seu@email.com" required>
                        </div>
                        <div class="mb-3">
                            <label for="senha" class="form-label">Senha *</label>
                            <input type="password" class="form-control" id="senha" name="senha" 
                                   placeholder="Digite uma senha segura" required minlength="6">
                        </div>
                        <div class="mb-3">
                            <label for="confirmar_senha" class="form-label">Confirmar senha *</label>
                            <input type="password" class="form-control" id="confirmar_senha" name="confirmar_senha" 
                                   placeholder="Digite a senha novamente" required minlength="6">
                        </div>
                        <button type="submit" class="btn btn-primary w-100 mb-3">Criar conta</button>
                        <div class="text-center">
                            <a href="?page=login" class="auth-link">Voltar para o login</a>
                        </div>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    <?php endif; ?>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Máscaras para CPF e telefone
        document.addEventListener('DOMContentLoaded', function() {
            // Máscara para CPF
            const cpfInput = document.getElementById('cpf');
            if (cpfInput) {
                cpfInput.addEventListener('input', function(e) {
                    let value = e.target.value.replace(/\D/g, '');
                    if (value.length > 11) value = value.substring(0, 11);
                    
                    if (value.length <= 11) {
                        value = value.replace(/(\d{3})(\d)/, '$1.$2');
                        value = value.replace(/(\d{3})(\d)/, '$1.$2');
                        value = value.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
                    }
                    
                    e.target.value = value;
                });
            }
            
            // Máscara para telefone
            const telefoneInput = document.getElementById('telefone');
            if (telefoneInput) {
                telefoneInput.addEventListener('input', function(e) {
                    let value = e.target.value.replace(/\D/g, '');
                    if (value.length > 11) value = value.substring(0, 11);
                    
                    if (value.length <= 11) {
                        if (value.length <= 2) {
                            value = value.replace(/^(\d{0,2})/, '($1');
                        } else if (value.length <= 7) {
                            value = value.replace(/^(\d{2})(\d{0,5})/, '($1) $2');
                        } else {
                            value = value.replace(/^(\d{2})(\d{5})(\d{0,4})/, '($1) $2-$3');
                        }
                    }
                    
                    e.target.value = value;
                });
            }
            
            // Auto-close alerts after 5 seconds
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }, 5000);
            });
        });
    </script>
</body>
</html>
