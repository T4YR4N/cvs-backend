import { OpenAPIRegistry } from '@asteasolutions/zod-to-openapi'
import express, { Request, Response, Router } from 'express'
import { z } from 'zod'

import { createAPIBody } from '@api-docs/openAPIBodyBuilder'
import { createApiResponse } from '@api-docs/openAPIResponseBuilders'
import { handleServiceResponse, validateRequest } from '@common/utils/httpHandlers'
import { webhookService } from '@modules/webhook/webhookService'

import { PostWebhookSchema, WebhookSchema } from './webhookModel'

export const webhookRegistry = new OpenAPIRegistry()

webhookRegistry.register('Webhook', WebhookSchema)

export const webhookRouter: Router = (() => {
    const router = express.Router()

    webhookRegistry.registerPath({
        method: 'get',
        path: '/webhooks',
        tags: ['Webhook'],
        responses: createApiResponse(z.array(WebhookSchema), 'Success'),
    })

    router.get('/', async (_req: Request, res: Response) => {
        const serviceResponse = await webhookService.findAll()
        handleServiceResponse(serviceResponse, res)
    })

    webhookRegistry.registerPath({
        method: 'post',
        path: '/webhook',
        tags: ['Webhook'],
        request: createAPIBody(PostWebhookSchema.shape.body, true),
        responses: createApiResponse(WebhookSchema, 'Success'),
    })

    router.post('/', validateRequest(PostWebhookSchema), async (req: Request, res: Response) => {
        const { body: webhook } = req as z.infer<typeof PostWebhookSchema>
        const serviceResponse = await webhookService.create(webhook)
        handleServiceResponse(serviceResponse, res)
    })

    return router
})()
