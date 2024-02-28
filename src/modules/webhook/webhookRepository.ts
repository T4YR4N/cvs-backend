import prisma from 'prisma/client'

import { Webhook } from '@modules/webhook/webhookModel'

export const webhookRepository = {
    findAllAsync: async (): Promise<Webhook[]> => {
        return prisma.webhook.findMany()
    },

    createAsync: async ({ url, sbomNameInQuery }: Omit<Webhook, 'id' | 'createdAt'>): Promise<Webhook> => {
        return prisma.webhook.create({
            data: {
                url,
                sbomNameInQuery,
            },
        })
    },
}
