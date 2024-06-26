import bodyParser from 'body-parser'
import cors from 'cors'
import dotenv from 'dotenv'
import express, { Express } from 'express'
import helmet from 'helmet'
import path from 'path'
import { pino } from 'pino'

import { openAPIRouter } from '@api-docs/openAPIRouter'
import errorHandler from '@common/middleware/errorHandler'
import rateLimiter from '@common/middleware/rateLimiter'
import requestLogger from '@common/middleware/requestLogger'
import { getCorsOrigin } from '@common/utils/envConfig'
import { healthCheckRouter } from '@modules/healthCheck/healthCheckRouter'
import { sbomRouter } from '@modules/sbom/sbomRouter'
import { scanRouter } from '@modules/scan/scanRouter'
import { webhookRouter } from '@modules/webhook/webhookRouter'

dotenv.config({
    path: path.resolve(__dirname, '../.env'),
})

const logger = pino({ name: 'server start' })
const app: Express = express()
const corsOrigin = getCorsOrigin()

// Middlewares
app.use(cors({ origin: [corsOrigin], credentials: true }))
app.use(helmet())
app.use(rateLimiter)

// Request logging
app.use(requestLogger())

// Parse JSON bodies
app.use(bodyParser.json({ limit: '50mb' }))

// Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }))

// Routes
app.use('/health-check', healthCheckRouter)
app.use('/sboms', sbomRouter)
app.use('/scans', scanRouter)
app.use('/webhook', webhookRouter)

// Swagger UI
app.use(openAPIRouter)

// Error handlers
app.use(errorHandler())

export { app, logger }
