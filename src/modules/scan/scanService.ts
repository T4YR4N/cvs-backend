import { ChunkType, Prisma, ScanStatus } from '@prisma/client'
import sha256 from 'crypto-js/sha256'
import prisma from 'prisma/client'

import Queue from '../../common/utils/queue'
import runShellCommand from '../../common/utils/runShellCommand'

export interface GrypeResult {
    matches: {
        matchDetails: any[]
        vulnerability: {
            id: string
        }
        artifact: {
            name: string
            version: string
        }
    }[]
}

export const scanQueue = new Queue<string>(() => scan())
export const evalQueue = new Queue<{ sbomId: string; result: string }>(() => evaluate())

const grypeScan = async (uuid: string) => {
    const path = `./data/sboms/${uuid}.sbom.json`
    const command = `grype --add-cpes-if-none -o json sbom:'${path}'`

    const result = await runShellCommand(command)

    return result
}

const scan = async () => {
    const uuid = await scanQueue.dequeue(async (uuid) => {
        console.log('scanning', uuid)

        const result = await grypeScan(uuid)

        evalQueue.enqueue({ sbomId: uuid, result })
    })

    if (uuid) {
        await scan()
    } else {
        console.log('queue is empty')
    }
}

const evaluate = async () => {
    const toEval = await evalQueue.dequeue(async ({ sbomId, result }) => {
        console.log('evaluating', sbomId)

        const sbom = await prisma.sbom.findUnique({
            where: {
                id: sbomId,
            },
        })

        if (!sbom) {
            return
        }

        const scan = await prisma.scan.findFirst({
            where: {
                sbomId,
                status: ScanStatus.PENDING,
            },
        })

        if (!scan) {
            return
        }

        const grypeResult: GrypeResult = JSON.parse(result)

        const mappedGrypeResult = grypeResult.matches.map(({ artifact, vulnerability, matchDetails }) => {
            const artifactHash = sha256(JSON.stringify(artifact)).toString()
            const vulnerabilityHash = sha256(JSON.stringify(vulnerability)).toString()
            const matchDetailsHash = sha256(JSON.stringify(matchDetails)).toString()

            const prismaArtifact: Prisma.JsonObject = artifact
            const prismaVulnerability: Prisma.JsonObject = vulnerability
            const prismaMatchDetails: Prisma.JsonArray = matchDetails

            return {
                artifactHash,
                vulnerabilityHash,
                matchDetailsHash,
                prismaArtifact,
                prismaVulnerability,
                prismaMatchDetails,
            }
        })

        const currentMatchesOfSbom = (
            await prisma.chunk.findMany({
                select: {
                    type: true,
                    createdAt: true,
                    match: {
                        select: {
                            vuln: true,
                            artifact: true,
                            details: true,
                            detailsHash: true,
                        },
                    },
                },
                where: {
                    scan: {
                        sbomId,
                    },
                },
                orderBy: {
                    createdAt: 'asc',
                },
            })
        ).map(({ match, type }) => ({
            chunkType: type,
            artifactHash: match.artifact.id,
            vulnerabilityHash: match.vuln.id,
            matchDetailsHash: match.detailsHash,
            prismaArtifact: match.artifact.value,
            prismaVulnerability: match.vuln.value,
            prismaMatchDetails: match.details,
        }))

        const newMatches = mappedGrypeResult.filter(({ artifactHash, vulnerabilityHash, matchDetailsHash }) => {
            const chunkedMatches = currentMatchesOfSbom.filter(
                (val) =>
                    val.artifactHash === artifactHash &&
                    val.vulnerabilityHash === vulnerabilityHash &&
                    val.matchDetailsHash === matchDetailsHash
            )

            // If there is an uneven number of matches, the match is currently in the database as a current one
            const matchIsCurrent = chunkedMatches.length % 2

            // A new match is one where the latest chunk is not an addition therefore having an even number of matches in the database
            return !matchIsCurrent
        })

        const removedMatches = currentMatchesOfSbom.filter(({ artifactHash, vulnerabilityHash, matchDetailsHash }) => {
            const chunkedMatches = mappedGrypeResult.filter(
                (val) =>
                    val.artifactHash === artifactHash &&
                    val.vulnerabilityHash === vulnerabilityHash &&
                    val.matchDetailsHash === matchDetailsHash
            )

            // If there is an uneven number of matches, the match is currently in the database as a current one
            const matchIsCurrent = chunkedMatches.length % 2

            // A removed match is one where the latest chunk is an addition therefore having an odd number of matches in the database
            return !matchIsCurrent
        })

        console.log('newMatches', newMatches.length)
        console.log('removedMatches', removedMatches.length)

        await prisma.$transaction(async (ctx) => {
            await ctx.artifact.createMany({
                data: newMatches.map((val) => ({
                    id: val.artifactHash,
                    value: val.prismaArtifact,
                })),
                skipDuplicates: true,
            })

            await ctx.vuln.createMany({
                data: newMatches.map((val) => ({
                    id: val.vulnerabilityHash,
                    value: val.prismaVulnerability,
                })),
                skipDuplicates: true,
            })

            await ctx.match.createMany({
                data: newMatches.map((val) => ({
                    detailsHash: val.matchDetailsHash,
                    details: val.prismaMatchDetails,
                    vulnId: val.vulnerabilityHash,
                    artifactId: val.artifactHash,
                })),
                skipDuplicates: true,
            })

            await ctx.chunk.createMany({
                data: newMatches.map((val) => ({
                    scanId: scan.id,
                    detailsHash: val.matchDetailsHash,
                    vulnId: val.vulnerabilityHash,
                    artifactId: val.artifactHash,
                    type: ChunkType.ADDITION,
                })),
            })

            await ctx.chunk.createMany({
                data: removedMatches.map((val) => ({
                    scanId: scan.id,
                    detailsHash: val.matchDetailsHash,
                    vulnId: val.vulnerabilityHash,
                    artifactId: val.artifactHash,
                    type: ChunkType.REMOVAL,
                })),
            })

            await ctx.scan.updateMany({
                data: {
                    status: ScanStatus.COMPLETED,
                },
                where: {
                    sbomId: sbomId,
                    status: ScanStatus.PENDING,
                },
            }) // this will only ever effect one

            return
        })
    })

    if (toEval) {
        await evaluate()
    } else {
        console.log('eval queue is empty')
    }
}
