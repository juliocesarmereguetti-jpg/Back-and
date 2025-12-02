-- Arquivo: fluxa.sql
-- Execute este script no MySQL para criar o banco de dados

CREATE DATABASE IF NOT EXISTS fluxa_financeiro DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE fluxa_financeiro;

-- Tabela de usuários
CREATE TABLE usuarios (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nome_completo VARCHAR(100) NOT NULL,
    cpf VARCHAR(14) UNIQUE NOT NULL,
    telefone VARCHAR(15),
    email VARCHAR(100) UNIQUE NOT NULL,
    senha VARCHAR(255) NOT NULL,
    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de transações
CREATE TABLE transacoes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    usuario_id INT NOT NULL,
    tipo ENUM('receita', 'despesa') NOT NULL,
    descricao VARCHAR(200) NOT NULL,
    valor DECIMAL(10,2) NOT NULL,
    categoria VARCHAR(50) NOT NULL,
    data_transacao DATE NOT NULL,
    observacoes TEXT,
    data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Inserir usuário de teste (senha: 123456)
INSERT INTO usuarios (nome_completo, cpf, telefone, email, senha) VALUES
('João Silva', '123.456.789-00', '(11) 99999-9999', 'joao@email.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),
('Maria Santos', '987.654.321-00', '(21) 98888-8888', 'maria@email.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');

-- Inserir transações de teste
INSERT INTO transacoes (usuario_id, tipo, descricao, valor, categoria, data_transacao) VALUES
(1, 'despesa', 'Supermercado Extra', 120.50, 'Alimentação', '2025-01-14'),
(1, 'receita', 'Salário Janeiro', 4500.00, 'Salário', '2025-01-31'),
(1, 'despesa', 'Uber', 25.80, 'Transporte', '2025-01-13'),
(1, 'despesa', 'Netflix', 32.90, 'Lazer', '2025-01-12'),
(1, 'receita', 'Freelance Site', 800.00, 'Freelance', '2025-01-20'),
(2, 'receita', 'Salário', 3800.00, 'Salário', '2025-01-30'),
(2, 'despesa', 'Aluguel', 1200.00, 'Moradia', '2025-01-05');
