# Zeon CLI Beta

Ferramenta multifuncional para operações de criptografia, varredura de rede, geolocalização de IP e muito mais, via linha de comando.

---

## Funcionalidades

- **Crypto**: Base64 encode/decode, MD5 e SHA-256 hash  
- **Portscan**: Verifica status básico de portas comuns  
- **IP Geo**: Consulta geolocalização via API pública  
- **Nmap Scan**: Executa scan avançado com nmap (requer nmap instalado)

---

## Requisitos

- Python 3.6+  
- Linux, macOS ou Windows  
- [nmap](https://nmap.org/) instalado para o comando nmap funcionar  
- Opcional: [colorama](https://pypi.org/project/colorama/) para saída colorida no Windows

---

## Instalação

Clone o repositório ou baixe o script `zeon.py`:

```bash
git clone https://github.com/seuusuario/zeon-toolkit.git
cd zeon-toolkit
```

Instale as dependências:

```bash
pip install requests colorama
```

---

## Uso

### Sintaxe geral

```bash
python zeon.py <comando> [opções]
```

### Comandos disponíveis

| Comando  | Descrição                                   |
| -------- | ------------------------------------------  |
| crypto   | Operações criptográficas                    |
| portscan | Verifica portas comuns em IP                |
| ipgeo    | Consulta geolocalização de IP               |
| nmap     | Scan avançado usando nmap (root/admin)      |

---

### Exemplos

- Base64 encode:

```bash
python zeon.py crypto --encode "minha mensagem secreta"
```

- MD5 hash:

```bash
python zeon.py crypto --md5 "senha123"
```

- Escanear portas no IP 192.168.0.1:

```bash
python zeon.py portscan --ip 192.168.0.1
```

- Consultar localização do IP 8.8.8.8:

```bash
python zeon.py ipgeo --ip 8.8.8.8
```

- Scan nmap no IP 192.168.0.1:

```bash
sudo python zeon.py nmap --ip 192.168.0.1
```

---

## Nota sobre permissões

Alguns comandos, especialmente `nmap`, podem exigir execução com privilégios administrativos (root no Linux/macOS, administrador no Windows).

---

## Contribuição

Contribuições são bem-vindas! Abra issues ou pull requests para melhorias, correções ou novos recursos.
