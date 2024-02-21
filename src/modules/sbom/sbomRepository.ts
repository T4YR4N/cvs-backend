import { Prisma } from '@prisma/client'
import prisma from 'prisma/client'

import { Sbom, SbomNoValue } from '@modules/sbom/sbomModel'

export const sbomRepository = {
    findAllAsync: async (): Promise<SbomNoValue[]> => {
        return prisma.sbom.findMany({
            select: {
                id: true,
                prettyName: true,
                createdAt: true,
            },
        })
    },

    findByIdAsync: async (id: string): Promise<Sbom | null> => {
        return prisma.sbom.findUnique({ where: { id } })
    },

    createAsync: async ({ prettyName, value }: Omit<Sbom, 'id' | 'createdAt'>): Promise<Sbom> => {
        return prisma.sbom.create({
            data: {
                prettyName,
                value: value as Prisma.JsonObject,
            },
        })
    },
}
