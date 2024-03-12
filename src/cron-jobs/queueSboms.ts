import { ScanStatus } from '@prisma/client'
import cron from 'node-cron'

import prisma from '../../prisma/client'
import { scanQueue } from '../modules/scan/scanService'

const queueSbomsCronJob = cron.schedule('* * * * *', async () => {
    queueSbomsCronJob.stop()

    const x = await prisma.sbom.findMany({
        select: {
            id: true,
        },
        where: {
            OR: [
                {
                    scans: {
                        none: {},
                    },
                },
                {
                    scans: {
                        every: {
                            AND: {
                                createdAt: {
                                    lt: new Date(Date.now() - 1000 * 60 * 60 * 12),
                                },
                                status: {
                                    not: ScanStatus.PENDING,
                                },
                            },
                        },
                    },
                },
            ],
        },
    })

    if (x.length !== 0) {
        await prisma.scan.createMany({
            data: x.map(({ id }) => ({
                sbomId: id,
                status: ScanStatus.PENDING,
            })),
        })

        x.forEach(({ id }) => {
            scanQueue.enqueue(id)
        })
    }

    queueSbomsCronJob.start()
})

export default queueSbomsCronJob
