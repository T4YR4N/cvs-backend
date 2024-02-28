import { StatusCodes } from 'http-status-codes'

import { ResponseStatus, ServiceResponse } from '@common/models/serviceResponse'
import { Webhook } from '@modules/webhook/webhookModel'
import { webhookRepository } from '@modules/webhook/webhookRepository'
import { logger } from '@src/server'

export const webhookService = {
    // Retrieves all webhooks from the database
    findAll: async (): Promise<ServiceResponse<Webhook[] | null>> => {
        try {
            const webhook = await webhookRepository.findAllAsync()
            if (!webhook) {
                return new ServiceResponse(ResponseStatus.Failed, 'No Webhooks found', null, StatusCodes.NOT_FOUND)
            }
            return new ServiceResponse<Webhook[]>(ResponseStatus.Success, 'Webhooks found', webhook, StatusCodes.OK)
        } catch (ex) {
            const errorMessage = `Error finding all webhooks: $${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },

    // Creates a new webhook
    create: async (webhook: Omit<Webhook, 'id' | 'createdAt'>): Promise<ServiceResponse<Webhook | null>> => {
        try {
            const newWebhook = await webhookRepository.createAsync(webhook)
            if (!newWebhook) {
                return new ServiceResponse(
                    ResponseStatus.Failed,
                    'Webhook not created',
                    null,
                    StatusCodes.INTERNAL_SERVER_ERROR
                )
            }
            return new ServiceResponse<Webhook>(
                ResponseStatus.Success,
                'Webhook created',
                newWebhook,
                StatusCodes.CREATED
            )
        } catch (ex) {
            const errorMessage = `Error creating webhook: ${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },
}
