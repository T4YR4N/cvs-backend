import { Prisma, ScanStatus } from '@prisma/client'
import axios from 'axios'
import CryptoJS from 'crypto-js'
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
            id?: string | undefined
            severity?: string | undefined
            cvss?:
                | {
                      metrics?: {
                          baseScore?: number | undefined
                          exploitabilityScore?: number | undefined
                          impactScore?: number | undefined
                      }
                  }[]
                | undefined
            fix?:
                | {
                      versions?: string[] | undefined
                      state?: string | undefined
                  }
                | undefined
        }
        matchDetails: {
            type?: string | undefined
        }[]
        artifact: {
            name?: string | undefined
            version?: string | undefined
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
    const command = `grype -o json sbom:'${path}' -c ./src/conf/grype.yaml`

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

export const computeGrypeResultDiffHash = (res: GrypeResult) => {
    /**
     * To ensure that the hash of reduced result is the same for every result that is equal the following normalizing measures are taken:
     * - All strings are converted to lower case
     * - All strings are trimmed
     * - The entire result is being put into one array and gets sorted as JSON objects are not specified to be ordered.
     */

    const normalizeString = (name: string, str: string | undefined) => `${name}:${str?.toLowerCase().trim() || ''}`
    const normalizeNumber = (name: string, num: number | undefined) => `${name}:${String(num || 0)}`

    /**
     * As JSON objects are not ordered the hash of the reduced result is not guaranteed to be the same for equal results.
     * Therefore all keys will be put into an array and sorted. As they are all just strings there is no need to sort them by their hash.
     */
    const newReducedResult = res.matches
        .reduce((acc, { vulnerability, matchDetails, artifact }) => {
            const normalizedCve = normalizeString('vulnId', vulnerability.id)

            acc.push(normalizedCve)
            acc.push(normalizeString('vulnSeverity', vulnerability.severity))
            vulnerability.cvss?.forEach((val) => {
                acc.push(normalizeNumber(`vulnCvss${normalizedCve}BaseScore`, val.metrics?.baseScore))
                acc.push(
                    normalizeNumber(`vulnCvss${normalizedCve}ExploitabilityScore`, val.metrics?.exploitabilityScore)
                )
                acc.push(normalizeNumber(`vulnCvss${normalizedCve}ImpactScore`, val.metrics?.impactScore))
            })
            vulnerability.fix?.versions?.forEach((v) => {
                acc.push(normalizeString(`vulnFixVersion${normalizedCve}`, v))
            })
            acc.push(normalizeString('vulnFixState', vulnerability.fix?.state))
            matchDetails?.forEach((md) => {
                acc.push(normalizeString(`matchDetailsType${normalizedCve}`, md.type))
            })
            acc.push(normalizeString('artifactName', artifact.name))
            acc.push(normalizeString('artifactVersion', artifact.version))

            return acc
        }, [] as string[])
        .sort()

    const resultAsBytes = CryptoJS.enc.Utf8.parse(newReducedResult.join(';'))

    const resultHash = sha256(resultAsBytes).toString()

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

        if (isNew) {
            const webhooks = await prisma.webhook.findMany()

            webhooks.forEach(async (webhook) => {
                try {
                    const { prettyName } = await prisma.sbom.findUniqueOrThrow({
                        select: {
                            prettyName: true,
                        },
                        where: {
                            id: sbomId,
                        },
                    })

                    const url = `${webhook.url}${webhook.sbomNameInQuery ? `?sbomName=${encodeURIComponent(prettyName)}` : ''}`

                    await axios.get(url)
                } catch (err) {
                    logger.error(`Error sending webhook to ${webhook.url}: ${(err as Error).message}`)
                }
            })

            logger.info('New result inserted for sbom', sbomId)
        }
    })

    if (insertedValue) {
        await insertNewResult()
    } else {
        logger.info('Queue to insert new result is empty; waiting for new tasks')
    }
}
