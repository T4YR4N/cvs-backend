import { getPort } from '@common/utils/envConfig'
import { app, logger } from '@src/server'

import queueSbomsCronJob from './cron-jobs/queueSboms'
import timeoutScansCronJob from './cron-jobs/scanTimeout'
import updateGrypeDbCronJob from './cron-jobs/updateGrypeDb'

const port = getPort()

const server = app.listen(port, () => {
    logger.info(`Server listening on port ${port}`)
})

const onCloseSignal = () => {
    logger.info('sigint received, shutting down')
    server.close(() => {
        logger.info('server closed')
        process.exit()
    })
    setTimeout(() => process.exit(1), 10000).unref() // Force shutdown after 10s
}

queueSbomsCronJob.start()
timeoutScansCronJob.start()
updateGrypeDbCronJob.start()

process.on('SIGINT', onCloseSignal)
process.on('SIGTERM', onCloseSignal)
