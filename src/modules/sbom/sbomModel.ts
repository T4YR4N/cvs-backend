import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'

import { commonValidations } from '@common/utils/commonValidation'

extendZodWithOpenApi(z)

export type Sbom = z.infer<typeof SbomSchema>
export const SbomSchema = z.object({
    id: commonValidations.uuid,
    prettyName: z.string(),
    createdAt: z.date(),
})

// Input Validation for 'GET sboms/:id' endpoint
export const GetSbomSchema = z.object({
    params: z.object({ id: commonValidations.uuid }),
})
