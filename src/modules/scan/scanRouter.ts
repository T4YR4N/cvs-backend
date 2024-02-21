import { OpenAPIRegistry } from '@asteasolutions/zod-to-openapi'
import express, { Request, Response, Router } from 'express'
import { z } from 'zod'

import { createApiResponse } from '@api-docs/openAPIResponseBuilders'
import { handleServiceResponse, validateRequest } from '@common/utils/httpHandlers'
import { scanService } from '@modules/scan/scanService'

import { GetScanSchema, GetScansSchema, ScanScheamaNoResult, ScanSchema } from './scanModel'

export const scanRegistry = new OpenAPIRegistry()

scanRegistry.register('Scan', ScanSchema)

export const scanRouter: Router = (() => {
    const router = express.Router()

    scanRegistry.registerPath({
        method: 'get',
        path: '/scans',
        tags: ['Scan'],
        request: { query: GetScansSchema.shape.query },
        responses: createApiResponse(z.array(ScanScheamaNoResult), 'Success'),
    })

    router.get('/', validateRequest(GetScansSchema), async (req: Request, res: Response) => {
        const { query } = req as z.infer<typeof GetScansSchema>

        const serviceResponse = await scanService.findAll(
            query.sbomId,
            Number(query.limit) || undefined,
            Number(query.offset) || undefined
        )
        handleServiceResponse(serviceResponse, res)
    })

    scanRegistry.registerPath({
        method: 'get',
        path: '/scans/{id}',
        tags: ['Scan'],
        request: { params: GetScanSchema.shape.params },
        responses: createApiResponse(ScanSchema, 'Success'),
    })

    router.get('/:id', validateRequest(GetScansSchema), async (req: Request, res: Response) => {
        const id = req.params.id as string
        const serviceResponse = await scanService.findById(id)
        handleServiceResponse(serviceResponse, res)
    })

    return router
})()
