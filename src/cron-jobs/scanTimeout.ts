import { ScanStatus } from '@prisma/client'
import cron from 'node-cron'

import { scanQueue } from '@modules/scan/scanService'

import prisma from '../../prisma/client'
import { logger } from '../server'

/**
 * sets scans that are older than 12 hours and pending to failed
 */
const scanTimeoutCronJob = cron.schedule('* * * * * *', async () => {
    scanTimeoutCronJob.stop()

    const scansToPossiblyTimeout = await prisma.scan.findMany({
        select: {
            id: true,
            sbomId: true,
        },
        where: {
            createdAt: {
                lt: new Date(Date.now() - 1000 * 60 * 60 * 12),
            },
            status: ScanStatus.PENDING,
        },
    })

    const scansStillInQueue = scansToPossiblyTimeout.filter(({ sbomId }) => scanQueue.search(sbomId))
    const scansToTimeout = scansToPossiblyTimeout
        .filter(({ id, sbomId }) => !scansStillInQueue.some((scan) => scan.sbomId === sbomId && scan.id === id))
        .map(({ id }) => id)

    if (scansStillInQueue.length !== 0) {
        logger.warn(`The following scans are in the scanning queue for more than 12 hours:
${scansStillInQueue.map((val) => `  - ${val.id} (sbom: ${val.sbomId})`).join('\n')}
This means that the queue is at capacity and the scans are not being processed in a timely manner.
		`)
    }

    if (scansToPossiblyTimeout.length !== 0) {
        await prisma.scan.updateMany({
            where: {
                id: {
                    in: scansToTimeout,
                },
            },
            data: {
                status: ScanStatus.FAILED,
            },
        })

        logger.error(`The following scans have timed out:
${scansToPossiblyTimeout.map((val) => `  - ${val.id} (sbom: ${val.sbomId})`).join('\n')}
		`)
    }

    scanTimeoutCronJob.start()
})

export default scanTimeoutCronJob
