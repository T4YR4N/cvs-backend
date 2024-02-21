/*
  Warnings:

  - The primary key for the `Match` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `id` on the `Match` table. All the data in the column will be lost.
  - You are about to drop the column `value` on the `Match` table. All the data in the column will be lost.
  - Added the required column `artifactId` to the `Chunk` table without a default value. This is not possible if the table is not empty.
  - Added the required column `vulnId` to the `Chunk` table without a default value. This is not possible if the table is not empty.
  - Added the required column `details` to the `Match` table without a default value. This is not possible if the table is not empty.
  - Added the required column `detailsHash` to the `Match` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_matchId_fkey";

-- DropIndex
DROP INDEX "Match_vulnId_artifactId_key";

-- DropIndex
DROP INDEX "Scan_sbomId_status_key";

-- AlterTable
ALTER TABLE "Chunk" ADD COLUMN     "artifactId" TEXT NOT NULL,
ADD COLUMN     "vulnId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "Match" DROP CONSTRAINT "Match_pkey",
DROP COLUMN "id",
DROP COLUMN "value",
ADD COLUMN     "details" JSONB NOT NULL,
ADD COLUMN     "detailsHash" TEXT NOT NULL,
ADD CONSTRAINT "Match_pkey" PRIMARY KEY ("vulnId", "artifactId", "detailsHash");

-- AddForeignKey
ALTER TABLE "Chunk" ADD CONSTRAINT "Chunk_matchId_vulnId_artifactId_fkey" FOREIGN KEY ("matchId", "vulnId", "artifactId") REFERENCES "Match"("detailsHash", "vulnId", "artifactId") ON DELETE RESTRICT ON UPDATE CASCADE;
