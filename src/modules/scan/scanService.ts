import { Prisma, ScanStatus } from '@prisma/client'
import sha256 from 'crypto-js/sha256'
import fs from 'fs'
import { StatusCodes } from 'http-status-codes'
import prisma from 'prisma/client'

import { ResponseStatus, ServiceResponse } from '@common/models/serviceResponse'
import { scanRepository } from '@modules/scan/scanRepository'
import { logger } from '@src/server'

import Queue from '../../common/utils/queue'
import runShellCommand from '../../common/utils/runShellCommand'

import { Scan } from './scanModel'

export const scanService = {
    // Retrieves scans by possibly providing an id of an associated sbom and/or a limit and offset
    findAll: async (
        sbomId?: string,
        limit?: number,
        offset?: number
    ): Promise<ServiceResponse<Omit<Scan, 'result'>[] | null>> => {
        try {
            const scans = await scanRepository.findAllAsync(sbomId, limit, offset)
            if (!scans.length) {
                return new ServiceResponse(ResponseStatus.Failed, 'No Scans found', null, StatusCodes.NOT_FOUND)
            }
            return new ServiceResponse<Omit<Scan, 'result'>[]>(
                ResponseStatus.Success,
                'Scans found',
                scans,
                StatusCodes.OK
            )
        } catch (ex) {
            const errorMessage = `Error finding all Scans: $${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },

    // Retrieves a single scan by its ID
    findById: async (id: string): Promise<ServiceResponse<Scan | null>> => {
        try {
            const scan = await scanRepository.findByIdAsync(id)
            if (!scan) {
                return new ServiceResponse(ResponseStatus.Failed, 'Scan not found', null, StatusCodes.NOT_FOUND)
            }
            return new ServiceResponse<Scan>(ResponseStatus.Success, 'Scan found', scan, StatusCodes.OK)
        } catch (ex) {
            const errorMessage = `Error finding Scan with id ${id}:, ${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },
}

/**
 * A narrowed type of the grype json output. This interface is not complete but encompasses all the fields used in this PoC.
 */
export interface GrypeResult {
    matches: {
        vulnerability: {
            id: string
            severity: string
            cvss: {
                metrics: {
                    baseScore: number
                    exploitabilityScore: number
                    impactScore: number
                }
            }[]
            fix: {
                versions: string[]
                state: string
            }
        }
        matchDetails: {
            type: string
        }[]
        artifact: {
            name: string
            version: string
        }
    }[]
}

/**
 * This queue stores all the sbom ids that need to be scanned. When the enqueued value is the first in the queue the scan function is called.
 * This will result in a recursive call of scan until the queue is empty.
 */
export const scanQueue = new Queue<string>(() => scan())

/**
 * This queue stores all the results of the grype scans. When the enqueued value is the first in the queue the insertNewResult function is called.
 * This will result in a recursive call of insertNewResult until the queue is empty.
 */
export const insertQueue = new Queue<{ sbomId: string; result: string }>(() => insertNewResult())

const grypeScan = async (uuid: string) => {
    const sbom = await prisma.sbom.findUnique({
        select: {
            value: true,
        },
        where: {
            id: uuid,
        },
    })

    if (!sbom || !sbom.value) {
        logger.error(`sbom for id ${uuid} not found`)
        await prisma.scan.updateMany({
            where: {
                sbomId: uuid,
                status: ScanStatus.PENDING,
            },
            data: {
                status: ScanStatus.FAILED,
            },
        })
        return
    }

    const path = `./data/sboms/${uuid}.sbom.json`
    const command = `grype --add-cpes-if-none -o json sbom:'${path}'`

    fs.writeFileSync(path, JSON.stringify(sbom.value))
    const result = await runShellCommand(command)
    fs.unlinkSync(path)

    return result
}

const scan = async () => {
    const uuid = await scanQueue.dequeue(async (uuid) => {
        logger.info('scanning', uuid)

        const result = await grypeScan(uuid)

        if (!result) {
            return
        }

        insertQueue.enqueue({ sbomId: uuid, result })
    })

    if (uuid) {
        await scan()
    } else {
        logger.info('Queue to scan sboms is empty; waiting for new tasks')
    }
}

const computeGrypeResultDiffHash = (res: GrypeResult) => {
    const reducedResult = res.matches.map(({ vulnerability, matchDetails, artifact }) => ({
        vulnerability: {
            id: vulnerability.id,
            severity: vulnerability.severity,
            cvss: vulnerability.cvss
                .map((val) => ({
                    metrics: {
                        baseScore: val.metrics.baseScore,
                        exploitabilityScore: val.metrics.exploitabilityScore,
                        impactScore: val.metrics.impactScore,
                    },
                }))
                .sort((a, b) => {
                    const aHash = sha256(JSON.stringify(a)).toString()
                    const bHash = sha256(JSON.stringify(b)).toString()

                    return aHash.localeCompare(bHash)
                }),
            fix: vulnerability.fix,
        },
        matchDetails: matchDetails
            .map((md) => ({
                type: md.type,
            }))
            .sort((a, b) => a.type.localeCompare(b.type)),
        artifact: {
            name: artifact.name,
            version: artifact.version,
        },
    }))

    const resultHash = sha256(JSON.stringify(reducedResult)).toString()

    return resultHash
}

const fetchResultHash = async (sbomId: string) => {
    const oldScan = await prisma.scan.findFirst({
        where: {
            sbomId,
            status: ScanStatus.COMPLETED,
            resultHash: {
                not: null,
            },
            result: {
                not: Prisma.JsonNull,
            },
        },
        orderBy: {
            createdAt: 'desc',
        },
    })

    const isFirstScan = oldScan === null

    if (isFirstScan) {
        return undefined
    }

    const resultHash = oldScan.resultHash
    const errorOccured = resultHash === null

    if (errorOccured) {
        throw new Error('unkown error') // This should just not happen as it is excluded by the query.
    }

    return resultHash
}

const insertNewResult = async () => {
    const insertedValue = await insertQueue.dequeue(async ({ sbomId, result }) => {
        const grypeResult: GrypeResult = JSON.parse(result)

        const prevResultHash = await fetchResultHash(sbomId)

        const currResHash = computeGrypeResultDiffHash(grypeResult)

        const isNew = !prevResultHash || prevResultHash !== currResHash

        await prisma.scan.updateMany({
            where: {
                sbomId,
                status: ScanStatus.PENDING,
            },
            data: {
                ...(isNew
                    ? {
                          result: grypeResult as unknown as Prisma.JsonObject,
                          resultHash: currResHash,
                      }
                    : {}),
                status: ScanStatus.COMPLETED,
            },
        })
    })

    if (insertedValue) {
        await insertNewResult()
    } else {
        logger.info('Queue to insert new result is empty; waiting for new tasks')
    }
}
