import { OpenAPIRegistry } from '@asteasolutions/zod-to-openapi'
import express, { Request, Response, Router } from 'express'
import { z } from 'zod'

import { createApiResponse } from '@api-docs/openAPIResponseBuilders'
import { handleServiceResponse, validateRequest } from '@common/utils/httpHandlers'
import { sbomService } from '@modules/sbom/sbomService'

import { GetSbomSchema, SbomSchema } from './sbomModel'

export const sbomRegistry = new OpenAPIRegistry()

sbomRegistry.register('Sbom', SbomSchema)

export const sbomRouter: Router = (() => {
    const router = express.Router()

    sbomRegistry.registerPath({
        method: 'get',
        path: '/sboms',
        tags: ['Sbom'],
        responses: createApiResponse(z.array(SbomSchema), 'Success'),
    })

    router.get('/', async (_req: Request, res: Response) => {
        const serviceResponse = await sbomService.findAll()
        handleServiceResponse(serviceResponse, res)
    })

    sbomRegistry.registerPath({
        method: 'get',
        path: '/sboms/{id}',
        tags: ['Sbom'],
        request: { params: GetSbomSchema.shape.params },
        responses: createApiResponse(SbomSchema, 'Success'),
    })

    router.get('/:id', validateRequest(GetSbomSchema), async (req: Request, res: Response) => {
        const id = req.params.id as string
        const serviceResponse = await sbomService.findById(id)
        handleServiceResponse(serviceResponse, res)
    })

    return router
})()
