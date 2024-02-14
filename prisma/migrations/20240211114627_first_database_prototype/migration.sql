-- CreateEnum
CREATE TYPE "ChunkType" AS ENUM ('ADDITION', 'REMOVAL');

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "sbomId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Chunk" (
    "scanId" TEXT NOT NULL,
    "matchId" TEXT NOT NULL,
    "type" "ChunkType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Chunk_pkey" PRIMARY KEY ("scanId","matchId")
);

-- CreateTable
CREATE TABLE "Match" (
    "id" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "vulnId" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Match_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Artifact" (
    "id" TEXT NOT NULL,
    "value" JSONB NOT NULL,

    CONSTRAINT "Artifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vuln" (
    "id" TEXT NOT NULL,
    "newVersionId" TEXT,
    "value" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Vuln_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Match_vulnId_artifactId_key" ON "Match"("vulnId", "artifactId");

-- CreateIndex
CREATE UNIQUE INDEX "Vuln_newVersionId_key" ON "Vuln"("newVersionId");

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_sbomId_fkey" FOREIGN KEY ("sbomId") REFERENCES "Sbom"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Chunk" ADD CONSTRAINT "Chunk_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Chunk" ADD CONSTRAINT "Chunk_matchId_fkey" FOREIGN KEY ("matchId") REFERENCES "Match"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_vulnId_fkey" FOREIGN KEY ("vulnId") REFERENCES "Vuln"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "Artifact"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vuln" ADD CONSTRAINT "Vuln_newVersionId_fkey" FOREIGN KEY ("newVersionId") REFERENCES "Vuln"("id") ON DELETE SET NULL ON UPDATE CASCADE;
