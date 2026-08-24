import {
  Prisma,
  PrismaClient,
  type Condominio,
  type Convidado,
  type Convite,
  type Morador
} from '@prisma/client';

import { createSoftDeleteRepository } from './soft-delete.js';

type RepositoryClient = Pick<
  PrismaClient,
  'condominio' | 'morador' | 'convidado' | 'convite'
>;

export function createPrismaRepositories(client: RepositoryClient) {
  return {
    condominio: createSoftDeleteRepository<
      Condominio,
      Prisma.CondominioWhereInput,
      Prisma.CondominioWhereUniqueInput,
      Prisma.CondominioOrderByWithRelationInput,
      Prisma.CondominioScalarFieldEnum,
      Prisma.BatchPayload
    >(client.condominio),
    morador: createSoftDeleteRepository<
      Morador,
      Prisma.MoradorWhereInput,
      Prisma.MoradorWhereUniqueInput,
      Prisma.MoradorOrderByWithRelationInput,
      Prisma.MoradorScalarFieldEnum,
      Prisma.BatchPayload
    >(client.morador),
    convidado: createSoftDeleteRepository<
      Convidado,
      Prisma.ConvidadoWhereInput,
      Prisma.ConvidadoWhereUniqueInput,
      Prisma.ConvidadoOrderByWithRelationInput,
      Prisma.ConvidadoScalarFieldEnum,
      Prisma.BatchPayload
    >(client.convidado),
    convite: createSoftDeleteRepository<
      Convite,
      Prisma.ConviteWhereInput,
      Prisma.ConviteWhereUniqueInput,
      Prisma.ConviteOrderByWithRelationInput,
      Prisma.ConviteScalarFieldEnum,
      Prisma.BatchPayload
    >(client.convite)
  };
}

const client = new PrismaClient();

export const prisma = createPrismaRepositories(client);

export function disconnectPrisma() {
  return client.$disconnect();
}
