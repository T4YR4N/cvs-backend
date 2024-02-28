import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'

import { commonValidations } from '@common/utils/commonValidation'

extendZodWithOpenApi(z)

export type Webhook = z.infer<typeof WebhookSchema>
export const WebhookSchema = z.object({
    id: commonValidations.uuid,
    url: z.string(),
    sbomNameInQuery: z.boolean(),
    createdAt: z.date(),
})

// Input Validation for 'POST webhook' endpoint
export const PostWebhookSchema = z.object({
    body: z.object({
        url: z.string(),
        sbomNameInQuery: z.boolean(),
    }),
})
