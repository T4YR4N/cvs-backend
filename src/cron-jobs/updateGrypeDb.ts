import cron from 'node-cron'

import runShellCommand from '@common/utils/runShellCommand'
import { logger } from '@src/server'

/**
 * updates the grype database every 12 hours
 */
const updateGrypeDbCronJob = cron.schedule('0 */12 * * *', async () => {
    const result = await runShellCommand('grype db update')

    logger.info('Grype DB updated', result)
})

export default updateGrypeDbCronJob
