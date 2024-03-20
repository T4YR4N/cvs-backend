import { describe, expect, test } from 'vitest'

import { computeGrypeResultDiffHash } from '../scanService'
import { GrypeResult } from '../scanService'

const scanResult = {
    matches: [
        {
            vulnerability: {
                id: 'CVE-2023-42366',
                dataSource: 'https://nvd.nist.gov/vuln/detail/CVE-2023-42366',
                namespace: 'nvd:cpe',
                severity: 'Medium',
                urls: ['https://bugs.busybox.net/show_bug.cgi?id=15874'],
                description:
                    'A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159.',
                cvss: [
                    {
                        source: 'nvd@nist.gov',
                        type: 'Primary',
                        version: '3.1',
                        vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
                        metrics: {
                            baseScore: 5.5,
                            exploitabilityScore: 1.8,
                            impactScore: 3.6,
                        },
                        vendorMetadata: {},
                    },
                    {
                        source: 'nvd@nist.gov',
                        type: 'Primary',
                        version: '3.1',
                        vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
                        metrics: {
                            baseScore: 10,
                            exploitabilityScore: 10,
                            impactScore: 10,
                        },
                        vendorMetadata: {},
                    },
                ],
                fix: {
                    versions: ['1.0', 'first'],
                    state: 'unknown',
                },
                advisories: [],
            },
            relatedVulnerabilities: [],
            matchDetails: [
                {
                    type: 'cpe-match',
                    matcher: 'apk-matcher',
                    searchedBy: {
                        namespace: 'nvd:cpe',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'],
                        Package: {
                            name: 'busybox',
                            version: '1.36.1-r15',
                        },
                    },
                    found: {
                        vulnerabilityID: 'CVE-2023-42366',
                        versionConstraint: '= 1.36.1 (unknown)',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'],
                    },
                },
                {
                    type: 'exact-direct-match',
                    matcher: 'apk-matcher',
                    searchedBy: {
                        namespace: 'nvd:cpe',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'],
                        Package: {
                            name: 'busybox',
                            version: '1.36.1-r15',
                        },
                    },
                    found: {
                        vulnerabilityID: 'CVE-2023-42366',
                        versionConstraint: '= 1.36.1 (unknown)',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'],
                    },
                },
            ],
            artifact: {
                id: 'b7175d7c76f2d4ac',
                name: 'busybox',
                version: '1.36.1-r15',
                type: 'apk',
                locations: [
                    {
                        path: '/lib/apk/db/installed',
                        layerID: 'sha256:3ce819cc49704a39ce4614b73a325ad6efff50e1754005a2a8f17834071027dc',
                    },
                ],
                language: '',
                licenses: ['GPL-2.0-only'],
                cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'],
                purl: 'pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64&distro=alpine-3.19.0',
                upstreams: [
                    {
                        name: 'busybox',
                    },
                ],
                metadataType: 'ApkMetadata',
                metadata: {
                    files: [],
                },
            },
        },
        {
            vulnerability: {
                id: 'CVE-2023-42365',
                dataSource: 'https://nvd.nist.gov/vuln/detail/CVE-2023-42365',
                namespace: 'nvd:cpe',
                severity: 'Medium',
                urls: ['https://bugs.busybox.net/show_bug.cgi?id=15871'],
                description:
                    'A use-after-free vulnerability was discovered in BusyBox v.1.36.1 via a crafted awk pattern in the awk.c copyvar function.',
                cvss: [
                    {
                        source: 'nvd@nist.gov',
                        type: 'Primary',
                        version: '3.1',
                        vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
                        metrics: {
                            baseScore: 5.5,
                            exploitabilityScore: 1.8,
                            impactScore: 3.6,
                        },
                        vendorMetadata: {},
                    },
                ],
                fix: {
                    versions: [],
                    state: 'unknown',
                },
                advisories: [],
            },
            relatedVulnerabilities: [],
            matchDetails: [
                {
                    type: 'cpe-match',
                    matcher: 'apk-matcher',
                    searchedBy: {
                        namespace: 'nvd:cpe',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'],
                        Package: {
                            name: 'busybox',
                            version: '1.36.1-r15',
                        },
                    },
                    found: {
                        vulnerabilityID: 'CVE-2023-42365',
                        versionConstraint: '= 1.36.1 (unknown)',
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'],
                    },
                },
            ],
            artifact: {
                id: 'b7175d7c76f2d4ac',
                name: 'busybox',
                version: '1.36.1-r15',
                type: 'apk',
                locations: [
                    {
                        path: '/lib/apk/db/installed',
                        layerID: 'sha256:3ce819cc49704a39ce4614b73a325ad6efff50e1754005a2a8f17834071027dc',
                    },
                ],
                language: '',
                licenses: ['GPL-2.0-only'],
                cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'],
                purl: 'pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64&distro=alpine-3.19.0',
                upstreams: [
                    {
                        name: 'busybox',
                    },
                ],
                metadataType: 'ApkMetadata',
                metadata: {
                    files: [],
                },
            },
        },
    ],
}

const testHash = '6762c667c0dc42b2e451a7955eb63a7112fb89a904dd09e135b25faa4bb4151c'

/*
 * Requirements:
 * - Same Hash for same vulnerabilities [done]
 * - Different hash for different vulnerabilities [done]
 * - case insesitivity for all strings [done]
 * - insensitive to trailing or leading whitespaces for all strings [done]
 * - order insensitivity for all arrays and objects [done]
 * - only sensitive to specific fields [done]
 * 		- vulnerability.id
 * 		- vulnerability.severity
 * 		- vulnerability.cvss.metrics.baseScore
 * 		- vulnerability.cvss.metrics.exploitabilityScore
 * 		- vulnerability.cvss.metrics.impactScore
 * 		- vulnerability.fix.versions
 * 		- vulnerability.fix.state
 * 		- matchDetails.type
 * 		- artifact.name
 * 		- artifact.version
 * - insensitive to possibly empty fields [done]
 */

describe('computeGrypeResultDiffHash ', () => {
    test('should return the correct hash if a specific result is passed', () => {
        const hash = computeGrypeResultDiffHash(scanResult)

        expect(hash).toBe(testHash)
    })

    test('should return the same hash if the vulnerabilities are in a different order', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [scanResult.matches[1], scanResult.matches[0]],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).toBe(testHash)
    })

    test('should return a different hash if one of the matches is not present', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [scanResult.matches[0]],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return the same hash if all strings are are in a different case', () => {
        const differentCaseFirstResult = {
            vulnerability: {
                id: 'CVE-2023-42366'.toLowerCase(),
                dataSource: 'https://nvd.nist.gov/vuln/detail/CVE-2023-42366'.toUpperCase(),
                namespace: 'nvd:cpe'.toUpperCase(),
                severity: 'Medium'.toUpperCase(),
                urls: ['https://bugs.busybox.net/show_bug.cgi?id=15874'].map((url) => url.toUpperCase()),
                description:
                    'A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159.'.toUpperCase(),
                cvss: [
                    {
                        source: 'nvd@nist.gov'.toUpperCase(),
                        type: 'Primary'.toUpperCase(),
                        version: '3.1'.toUpperCase(),
                        vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H'.toLowerCase(),
                        metrics: {
                            baseScore: 5.5,
                            exploitabilityScore: 1.8,
                            impactScore: 3.6,
                        },
                        vendorMetadata: {},
                    },
                    {
                        source: 'nvd@nist.gov'.toUpperCase(),
                        type: 'Primary'.toUpperCase(),
                        version: '3.1'.toUpperCase(),
                        vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H'.toLowerCase(),
                        metrics: {
                            baseScore: 10,
                            exploitabilityScore: 10,
                            impactScore: 10,
                        },
                        vendorMetadata: {},
                    },
                ],
                fix: {
                    versions: ['1.0', 'first'].map((version) => version.toUpperCase()),
                    state: 'unknown'.toUpperCase(),
                },
                advisories: [],
            },
            relatedVulnerabilities: [],
            matchDetails: [
                {
                    type: 'cpe-match'.toUpperCase(),
                    matcher: 'apk-matcher'.toUpperCase(),
                    searchedBy: {
                        namespace: 'nvd:cpe'.toUpperCase(),
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'].map((cpe) => cpe.toUpperCase()),
                        Package: {
                            name: 'busybox'.toUpperCase(),
                            version: '1.36.1-r15'.toUpperCase(),
                        },
                    },
                    found: {
                        vulnerabilityID: 'CVE-2023-42366'.toLowerCase(),
                        versionConstraint: '= 1.36.1 (unknown)'.toUpperCase(),
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'].map((cpe) => cpe.toUpperCase()),
                    },
                },
                {
                    type: 'exact-direct-match'.toUpperCase(),
                    matcher: 'apk-matcher'.toUpperCase(),
                    searchedBy: {
                        namespace: 'nvd:cpe'.toUpperCase(),
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'.toUpperCase()],
                        Package: {
                            name: 'busybox'.toUpperCase(),
                            version: '1.36.1-r15'.toUpperCase(),
                        },
                    },
                    found: {
                        vulnerabilityID: 'CVE-2023-42366'.toUpperCase(),
                        versionConstraint: '= 1.36.1 (unknown)'.toUpperCase(),
                        cpes: ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'.toUpperCase()],
                    },
                },
            ],
            artifact: {
                id: 'b7175d7c76f2d4ac'.toUpperCase(),
                name: 'busybox'.toUpperCase(),
                version: '1.36.1-r15'.toUpperCase(),
                type: 'apk'.toUpperCase(),
                locations: [
                    {
                        path: '/lib/apk/db/installed'.toUpperCase(),
                        layerID:
                            'sha256:3ce819cc49704a39ce4614b73a325ad6efff50e1754005a2a8f17834071027dc'.toUpperCase(),
                    },
                ],
                language: '',
                licenses: ['GPL-2.0-only'.toUpperCase()],
                cpes: ['cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*'.toUpperCase()],
                purl: 'pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64&distro=alpine-3.19.0'.toUpperCase(),
                upstreams: [
                    {
                        name: 'busybox'.toUpperCase(),
                    },
                ],
                metadataType: 'ApkMetadata'.toUpperCase(),
                metadata: {
                    files: [],
                },
            },
        } as unknown as GrypeResult['matches'][0]

        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [differentCaseFirstResult, scanResult.matches[1]],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).toBe(testHash)
    })

    test('should return the same hash if all strings have trailing and leading whitespaces', () => {
        const differentCaseFirstResult = {
            vulnerability: {
                id: ' CVE-2023-42366 ',
                dataSource: ' https://nvd.nist.gov/vuln/detail/CVE-2023-42366 ',
                namespace: ' nvd:cpe ',
                severity: ' Medium ',
                urls: [' https://bugs.busybox.net/show_bug.cgi?id=15874 '],
                description:
                    ' A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159. ',
                cvss: [
                    {
                        source: ' nvd@nist.gov ',
                        type: ' Primary ',
                        version: ' 3.1 ',
                        vector: ' CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H ',
                        metrics: {
                            baseScore: 5.5,
                            exploitabilityScore: 1.8,
                            impactScore: 3.6,
                        },
                        vendorMetadata: {},
                    },
                    {
                        source: ' nvd@nist.gov ',
                        type: ' Primary ',
                        version: ' 3.1 ',
                        vector: ' CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H ',
                        metrics: {
                            baseScore: 10,
                            exploitabilityScore: 10,
                            impactScore: 10,
                        },
                        vendorMetadata: {},
                    },
                ],
                fix: {
                    versions: [' 1.0 ', ' first '],
                    state: ' unknown ',
                },
                advisories: [],
            },
            relatedVulnerabilities: [],
            matchDetails: [
                {
                    type: ' cpe-match ',
                    matcher: ' apk-matcher ',
                    searchedBy: {
                        namespace: ' nvd:cpe ',
                        cpes: [' cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:* '].map((cpe) => cpe),
                        Package: {
                            name: ' busybox ',
                            version: ' 1.36.1-r15 ',
                        },
                    },
                    found: {
                        vulnerabilityID: ' CVE-2023-42366 ',
                        versionConstraint: ' = 1.36.1 (unknown) ',
                        cpes: [' cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:* '].map((cpe) => cpe),
                    },
                },
                {
                    type: ' exact-direct-match ',
                    matcher: ' apk-matcher ',
                    searchedBy: {
                        namespace: ' nvd:cpe ',
                        cpes: [' cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:* '],
                        Package: {
                            name: ' busybox ',
                            version: ' 1.36.1-r15 ',
                        },
                    },
                    found: {
                        vulnerabilityID: ' CVE-2023-42366 ',
                        versionConstraint: ' = 1.36.1 (unknown) ',
                        cpes: [' cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:* '],
                    },
                },
            ],
            artifact: {
                id: ' b7175d7c76f2d4ac ',
                name: ' busybox ',
                version: ' 1.36.1-r15 ',
                type: ' apk ',
                locations: [
                    {
                        path: ' /lib/apk/db/installed ',
                        layerID: ' sha256:3ce819cc49704a39ce4614b73a325ad6efff50e1754005a2a8f17834071027dc ',
                    },
                ],
                language: ' ',
                licenses: [' GPL-2.0-only '],
                cpes: [' cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:* '],
                purl: ' pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64&distro=alpine-3.19.0 ',
                upstreams: [
                    {
                        name: ' busybox ',
                    },
                ],
                metadataType: ' ApkMetadata ',
                metadata: {
                    files: [],
                },
            },
        } as unknown as GrypeResult['matches'][0]

        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [differentCaseFirstResult, scanResult.matches[1]],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).toBe(testHash)
    })

    test('should return the same hash if the vulnerabilities are the same, but the fields are in a different order', () => {
        const { matchDetails, artifact, vulnerability } = scanResult.matches[0]

        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    matchDetails,
                    artifact: {
                        version: artifact.version,
                        name: artifact.name,
                    },
                    vulnerability: {
                        severity: vulnerability.severity,
                        id: vulnerability.id,
                        fix: vulnerability.fix,
                        cvss: vulnerability.cvss,
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).toBe(testHash)
    })

    test('should return the same hash if the vulnerabilities are the same, but all arrays are in a different order', () => {
        const { matchDetails, artifact, vulnerability } = scanResult.matches[0]

        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    matchDetails: [matchDetails[1], matchDetails[0]],
                    artifact: {
                        ...artifact,
                    },
                    vulnerability: {
                        ...vulnerability,
                        fix: {
                            state: vulnerability.fix.state,
                            versions: [vulnerability.fix.versions[1], vulnerability.fix.versions[0]],
                        },
                        cvss: [vulnerability.cvss[1], vulnerability.cvss[0]],
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.id', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        id: 'CVE-2023-42367',
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.severity', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        severity: 'High',
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.css.metrics[number].baseScore', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        cvss: [
                            {
                                ...scanResult.matches[0].vulnerability.cvss[0],
                                metrics: {
                                    ...scanResult.matches[0].vulnerability.cvss[0].metrics,
                                    baseScore: 1,
                                },
                            },
                            scanResult.matches[0].vulnerability.cvss[1],
                        ],
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.css.metrics[number].exploitabilityScore', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        cvss: [
                            {
                                ...scanResult.matches[0].vulnerability.cvss[0],
                                metrics: {
                                    ...scanResult.matches[0].vulnerability.cvss[0].metrics,
                                    exploitabilityScore: 1,
                                },
                            },
                            scanResult.matches[0].vulnerability.cvss[1],
                        ],
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.css.metrics[number].impactScore', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        cvss: [
                            {
                                ...scanResult.matches[0].vulnerability.cvss[0],
                                metrics: {
                                    ...scanResult.matches[0].vulnerability.cvss[0].metrics,
                                    impactScore: 1,
                                },
                            },
                            scanResult.matches[0].vulnerability.cvss[1],
                        ],
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.fix.versions', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        fix: {
                            ...scanResult.matches[0].vulnerability.fix,
                            versions: ['1.0', 'second'],
                        },
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different vulnerability.fix.state', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    vulnerability: {
                        ...scanResult.matches[0].vulnerability,
                        fix: {
                            ...scanResult.matches[0].vulnerability.fix,
                            state: 'fixed',
                        },
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different matchDetails[number].type', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    matchDetails: [
                        {
                            ...scanResult.matches[0].matchDetails[0],
                            type: 'exact-indirect-match',
                        },
                        scanResult.matches[0].matchDetails[1],
                    ],
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different artifact.name', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    artifact: {
                        ...scanResult.matches[0].artifact,
                        name: 'busybox2',
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a different hash if one of the matches has a different artifact.version', () => {
        const moddedTestResult: GrypeResult = {
            ...scanResult,
            matches: [
                {
                    ...scanResult.matches[0],
                    artifact: {
                        ...scanResult.matches[0].artifact,
                        version: '1.36.1-r16',
                    },
                },
                scanResult.matches[1],
            ],
        }

        const hash = computeGrypeResultDiffHash(moddedTestResult)

        expect(hash).not.toBe(testHash)
    })

    test('should return a hash even if the vulnerability, matchDetails or artifact attributes dont have the expected attributes', () => {
        const moddedScanResult = {
            matches: [{ vulnerability: {}, matchDetails: [], artifact: {} }],
        }

        const testFunc = () => {
            const hash = computeGrypeResultDiffHash(moddedScanResult)

            expect(hash).toBe('92c2befc84595211d17ae26026242c5f2c31340722e3fb9ffb95a7d0218b0967')
        }

        expect(testFunc).not.toThrow()
    })
})
