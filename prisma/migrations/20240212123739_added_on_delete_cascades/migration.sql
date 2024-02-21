-- DropForeignKey
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_scanId_fkey";

-- DropForeignKey
ALTER TABLE "Match" DROP CONSTRAINT "Match_artifactId_fkey";

-- DropForeignKey
ALTER TABLE "Match" DROP CONSTRAINT "Match_vulnId_fkey";

-- DropForeignKey
ALTER TABLE "Scan" DROP CONSTRAINT "Scan_sbomId_fkey";

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_sbomId_fkey" FOREIGN KEY ("sbomId") REFERENCES "Sbom"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Chunk" ADD CONSTRAINT "Chunk_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_vulnId_fkey" FOREIGN KEY ("vulnId") REFERENCES "Vuln"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "Artifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;
