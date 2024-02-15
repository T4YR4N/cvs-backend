import prisma from 'prisma/client'

import { Scan } from './scanModel'

export const scanRepository = {
    findByIdAsync: async (scanId: string): Promise<Scan | null> => {
        return prisma.scan.findUnique({
            where: { id: scanId },
        })
    },

    findAllAsync: async (sbomId?: string, limit?: number, offset?: number): Promise<Omit<Scan, 'result'>[]> => {
        return prisma.scan.findMany({
            select: {
                id: true,
                sbomId: true,
                createdAt: true,
                status: true,
                resultHash: true,
            },
            ...(sbomId ? { where: { sbomId } } : {}),
            ...(limit && offset ? { take: limit, skip: offset } : {}),
        })
    },
}
