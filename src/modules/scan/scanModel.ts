import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { ScanStatus } from '@prisma/client'
import { z } from 'zod'

import { commonValidations } from '@common/utils/commonValidation'

extendZodWithOpenApi(z)

export type Scan = z.infer<typeof ScanSchema>
export const ScanSchema = z.object({
    id: commonValidations.uuid,
    sbomId: commonValidations.uuid,
    createdAt: z.date(),
    status: z.literal(ScanStatus.COMPLETED).or(z.literal(ScanStatus.FAILED)).or(z.literal(ScanStatus.PENDING)),
    result: z.any().or(z.null()),
    resultHash: z.string().or(z.null()),
})

export type ScanNoResult = z.infer<typeof ScanScheamaNoResult>
export const ScanScheamaNoResult = z.object({
    id: commonValidations.uuid,
    sbomId: commonValidations.uuid,
    createdAt: z.date(),
    status: z.literal(ScanStatus.COMPLETED).or(z.literal(ScanStatus.FAILED)).or(z.literal(ScanStatus.PENDING)),
    resultHash: z.string().or(z.null()),
})

// Input Validation for 'GET scans/:id' endpoint
export const GetScanSchema = z.object({
    params: z.object({ id: commonValidations.uuid }),
})

// Input Validation for 'GET scans' endpoint
export const GetScansSchema = z.object({
    query: z.object({
        limit: z.number().optional(),
        offset: z.number().optional(),
        sbomId: commonValidations.uuid.optional(),
    }),
})
