import { z } from 'zod'

export const commonValidations = {
    uuid: z.string().uuid(),
}
