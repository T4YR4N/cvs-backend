import { z } from 'zod'

export const createAPIBody = (schema: z.ZodTypeAny, required: boolean) => {
    return {
        body: {
            required,
            content: {
                'application/json': { schema },
            },
        },
    }
}
