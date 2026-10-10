import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { PrismaClient, Prisma } from "@prisma/client";
import { z } from "zod";

const prisma = new PrismaClient();

const server = new McpServer({
  name: "igreja-mcp-server",
  version: "1.1.0"
});

// Cadastro Seguro com Consentimento LGPD
server.tool(
  "cadastrar_membro_seguro",
  "Cadastra um membro exigindo o consentimento explícito da LGPD.",
  {
    igreja_id: z.string().uuid("ID da Igreja inválido"),
    rede_id: z.string().uuid("ID da Rede inválido"),
    cpf: z.string().regex(/^\d{11}$/, "O CPF deve conter exatamente 11 dígitos numéricos"),
    nome: z.string().min(2, "Nome muito curto").trim(),
    sobrenome: z.string().default("").transform(s => s.trim()),
    telefone_whatsapp: z.string().min(8, "Telefone inválido").trim(),
    termo_lgpd_aceite: z.boolean().describe("Confirmação obrigatória do aceite do termo LGPD"),
    versao_termo_lgpd: z.string().default("v1.0")
  },
  async (args) => {
    if (!args.termo_lgpd_aceite) {
      return {
        content: [{ 
          type: "text", 
          text: "ERRO DE CONFORMIDADE: O cadastro só pode ser realizado com o consentimento do titular (LGPD Art. 7º, I e Art. 11, I)." 
        }],
        isError: true
      };
    }

    try {
      const novoMembro = await prisma.membro.create({
        data: {
          igreja_id: args.igreja_id,
          rede_id: args.rede_id,
          cpf: args.cpf,
          nome: args.nome,
          sobrenome: args.sobrenome,
          telefone_whatsapp: args.telefone_whatsapp,
          termo_lgpd_aceite: true,
          data_aceite_lgpd: new Date(),
          versao_termo_lgpd: args.versao_termo_lgpd
        },
        select: { id: true, nome: true, criado_em: true }
      });

      return {
        content: [{
          type: "text",
          text: `Membro ${novoMembro.nome} cadastrado com sucesso. ID: ${novoMembro.id}. Biometria deve ser enviada via canal seguro.`
        }]
      };
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
        return {
          content: [{ type: "text", text: "ERRO: Já existe um membro cadastrado com este CPF." }],
          isError: true
        };
      }
      return {
        content: [{ type: "text", text: `Erro ao cadastrar: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true
      };
    }
  }
);

// Direito ao Esquecimento (LGPD)
server.tool(
  "anonimizar_membro",
  "Aplica o direito ao esquecimento (LGPD Art. 18, VI): elimina biometria, foto e anonimiza dados.",
  { 
    membro_id: z.string().uuid("ID do Membro inválido"),
    igreja_id: z.string().uuid("ID da Igreja para isolamento de tenant")
  },
  async ({ membro_id, igreja_id }) => {
    try {
      const resultado = await prisma.$executeRaw`
        UPDATE "Membro"
        SET nome = 'ANONIMIZADO',
            sobrenome = 'ANONIMIZADO',
            cpf = CONCAT('anon_', md5(random()::text || clock_timestamp()::text)),
            telefone_whatsapp = '',
            foto_perfil_url = NULL,
            biometria_facial = NULL,
            dados_anonimizados = true,
            revogado_lgpd_em = NOW()
        WHERE id = ${membro_id} 
          AND igreja_id = ${igreja_id}
          AND dados_anonimizados = false;
      `;

      if (resultado === 0) {
        return {
          content: [{ type: "text", text: "Nenhum membro ativo encontrado com o ID e Igreja fornecidos." }],
          isError: true
        };
      }

      return {
        content: [{ 
          type: "text", 
          text: `Direito ao esquecimento aplicado com sucesso para o membro ${membro_id}.` 
        }]
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Erro ao anonimizar: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true
      };
    }
  }
);

// Consulta Segura com Mascaramento de PII
server.tool(
  "consultar_membro_seguro",
  "Consulta dados de um membro aplicando máscara de proteção em dados pessoais (PII).",
  {
    membro_id: z.string().uuid(),
    igreja_id: z.string().uuid()
  },
  async ({ membro_id, igreja_id }) => {
    const membro = await prisma.membro.findFirst({
      where: { id: membro_id, igreja_id, dados_anonimizados: false },
      select: {
        id: true,
        nome: true,
        sobrenome: true,
        cpf: true,
        telefone_whatsapp: true,
        termo_lgpd_aceite: true,
        criado_em: true
      }
    });

    if (!membro) {
      return { content: [{ type: "text", text: "Membro não encontrado ou anonimizado." }], isError: true };
    }

    const cpfMascarado = membro.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.***.***-$4");
    const telMascarado = membro.telefone_whatsapp.replace(/(\d{2})(\d{5})(\d{4})/, "($1) 9****-$3");

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          id: membro.id,
          nome: `${membro.nome} ${membro.sobrenome}`.trim(),
          cpf: cpfMascarado,
          telefone: telMascarado,
          termo_lgpd_ativo: membro.termo_lgpd_aceite,
          cadastrado_em: membro.criado_em
        }, null, 2)
      }]
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[MCP SERVER] Servidor Seguro igreja-mcp-server iniciado via STDIO.");
}

process.on("SIGINT", async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  process.exit(0);
});

main().catch((err) => {
  console.error("[MCP SERVER ERROR]", err);
  process.exit(1);
});
