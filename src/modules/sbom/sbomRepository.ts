import prisma from 'prisma/client'

import { Sbom } from '@modules/sbom/sbomModel'

export const sbomRepository = {
    findAllAsync: async (): Promise<Sbom[]> => {
        return prisma.sbom.findMany()
    },

    findByIdAsync: async (id: string): Promise<Sbom | null> => {
        return prisma.sbom.findUnique({ where: { id } })
    },
}
